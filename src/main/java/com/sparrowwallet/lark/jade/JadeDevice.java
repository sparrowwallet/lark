package com.sparrowwallet.lark.jade;

import co.nstant.in.cbor.CborBuilder;
import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.CborEncoder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.builder.ArrayBuilder;
import co.nstant.in.cbor.builder.MapBuilder;
import co.nstant.in.cbor.model.*;
import co.nstant.in.cbor.model.Number;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fazecast.jSerialComm.SerialPort;
import com.fazecast.jSerialComm.SerialPortTimeoutException;
import com.google.common.base.CharMatcher;
import com.sparrowwallet.drongo.*;
import com.sparrowwallet.drongo.crypto.ChildNumber;
import com.sparrowwallet.drongo.protocol.ScriptType;
import com.sparrowwallet.lark.DeviceException;
import com.sparrowwallet.lark.DeviceProtocolException;
import com.sparrowwallet.lark.Lark;
import com.sparrowwallet.lark.net.HttpClientService;
import com.sparrowwallet.lark.net.http.client.AsyncUtil;
import com.sparrowwallet.lark.net.http.client.HttpUsage;
import com.sparrowwallet.lark.net.http.client.IHttpClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.*;
import java.util.Map;

public class JadeDevice implements Closeable {
    private static final Logger log = LoggerFactory.getLogger(JadeDevice.class);

    private SerialPort serialPort;
    private final SecureRandom secureRandom = new SecureRandom();
    private final ObjectMapper mapper = new ObjectMapper();

    public JadeDevice(SerialPort serialPort) throws DeviceException {
        this.serialPort = serialPort;
        connect();
    }

    public JadeVersion getVersionInfo() throws DeviceException {
        Map<String, Object> params = Map.of("nonblocking", Boolean.TRUE);
        return rpc("get_version_info", params, JadeVersion.class);
    }

    public boolean addEntropy() throws DeviceException {
        byte[] entropy = new byte[32];
        secureRandom.nextBytes(entropy);
        Map<String, Object> params = Map.of("entropy", entropy);
        return rpc("add_entropy", params, Boolean.class);
    }

    public boolean authUser(Network network) throws DeviceException {
        Map<String, Object> params = Map.of("network", network.toString(), "epoch", System.currentTimeMillis() / 1000);
        return rpc("auth_user", params, new HttpRequest(), true, Boolean.class);
    }

    public ExtendedKey getXpub(Network network, String path) throws DeviceException {
        List<Long> derivationPath = getPathAsInts(path);
        String xpub = rpc("get_xpub", Map.of("network", network.toString(), "path", derivationPath), String.class);
        return ExtendedKey.fromDescriptor(xpub);
    }

    public byte[] signTransaction(Network network, byte[] psbtBytes) throws DeviceException {
        Map<String, Object> params = Map.of("network", network.toString(), "psbt", psbtBytes);
        String inputId = Integer.toString(secureRandom.nextInt(899999) + 100000);
        Map<String, Object> request = buildRequest(inputId, "sign_psbt", params);
        writeRequest(request);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        while(true) {
            Map<String, Object> reply = readResponse(true);
            validateReply(request, reply);
            Object result = getResultOrThrow(reply);
            if(result != null) {
                baos.writeBytes(mapper.convertValue(result, byte[].class));
            }

            if(reply.get("seqnum") == null || reply.get("seqnum").equals(reply.get("seqlen"))) {
                break;
            }

            String newId = Integer.toString(secureRandom.nextInt(899999) + 100000);
            params = Map.of("origid", inputId, "orig", "sign_psbt",
                    "seqnum", Integer.parseInt(reply.get("seqnum").toString()) + 1, "seqlen", reply.get("seqlen"));
            request = buildRequest(newId, "get_extended_data", params);
            writeRequest(request);
        }

        return baos.toByteArray();
    }

    public String signMessage(String message, String path) throws DeviceException {
        List<Long> derivationPath = getPathAsInts(path);
        return rpc("sign_message", Map.of("message", message, "path", derivationPath), null, true, String.class);
    }

    public String displaySinglesigAddress(Network network, String path, ScriptType scriptType) throws DeviceException {
        List<Long> derivationPath = getPathAsInts(path);
        String addressVariant = getAddressVariant(scriptType);
        return rpc("get_receive_address", Map.of("network", network.toString(), "variant", addressVariant, "path", derivationPath), null, true, String.class);
    }

    public String displayMultisigAddress(Network network, String name, OutputDescriptor outputDescriptor) throws DeviceException {
        List<List<Long>> paths = outputDescriptor.getExtendedPublicKeys().stream().map(outputDescriptor::getChildDerivationPath).map(JadeDevice::getPathAsInts).toList();
        return rpc("get_receive_address", Map.of("network", network.toString(), "paths", paths, "multisig_name", name), null, true, String.class);
    }

    public boolean registerMultisig(Network network, String name, OutputDescriptor outputDescriptor) throws DeviceException {
        String addressVariant = getAddressVariant(outputDescriptor);
        int threshold = outputDescriptor.getMultisigThreshold();
        List<Map<String, Object>> signers = new ArrayList<>();
        for(ExtendedKey extKey : outputDescriptor.getExtendedPublicKeys()) {
            Map<String, Object> signer = new LinkedHashMap<>();
            KeyDerivation keyDerivation = outputDescriptor.getKeyDerivation(extKey);
            signer.put("fingerprint", Utils.hexToBytes(keyDerivation.getMasterFingerprint()));
            signer.put("derivation", getPathAsInts(keyDerivation.getDerivationPath()));
            signer.put("xpub", extKey.getExtendedKey());
            signer.put("path", List.of());
            signers.add(signer);
        }

        return rpc("register_multisig", Map.of("network", network.toString(), "multisig_name", name,
                "descriptor", Map.of("variant", addressVariant, "sorted", true, "threshold", threshold, "signers", signers)), null, true, Boolean.class);
    }

    private static List<Long> getPathAsInts(String path) {
        List<ChildNumber> derivation = KeyDerivation.parsePath(path);
        return derivation.stream().map(num -> Integer.toUnsignedLong(num.i())).toList();
    }

    private String getAddressVariant(ScriptType scriptType) {
        return scriptType.getDescriptor() + "k" + scriptType.getCloseDescriptor();
    }

    private String getAddressVariant(OutputDescriptor outputDescriptor) {
        StringBuilder builder = new StringBuilder();
        builder.append(outputDescriptor.getScriptType().getDescriptor());
        if(outputDescriptor.isMultisig()) {
            builder.append(ScriptType.MULTISIG.getDescriptor());
            builder.append("k");
            builder.append(ScriptType.MULTISIG.getCloseDescriptor());
        }
        builder.append(outputDescriptor.getScriptType().getCloseDescriptor());
        return builder.toString().replace("sortedmulti", "multi");
    }

    public void connect() {
        serialPort.openPort();
        serialPort.setComPortParameters(115200, 8, 1, 0);
        serialPort.setComPortTimeouts(SerialPort.TIMEOUT_READ_SEMI_BLOCKING, 500, 1000);
        serialPort.clearRTS();
        serialPort.clearDTR();
    }

    @Override
    public void close() {
        if(serialPort != null) {
            if(serialPort.isOpen()) {
                serialPort.clearRTS();
                serialPort.clearDTR();
                serialPort.closePort();
            }
            serialPort = null;
        }
    }

    private <T> T rpc(String method, Map<String, Object> params, Class<T> toValueType) throws DeviceException {
        return rpc(method, params, null, false, toValueType);
    }

    private <T> T rpc(String method, Map<String, Object> params, RpcCallback rpcCallback, boolean longTimeout, Class<T> toValueType) throws DeviceException {
        Object result = rpc(method, params, rpcCallback, longTimeout);
        return mapper.convertValue(result, toValueType);
    }

    private Object rpc(String method, Map<String, Object> params, RpcCallback rpcCallback, boolean longTimeout) throws DeviceException {
        return rpc(method, params, Integer.toString(secureRandom.nextInt(899999) + 100000), rpcCallback, longTimeout);
    }

    private Object rpc(String method, Map<String, Object> params, String inputId, RpcCallback rpcCallback, boolean longTimeout) throws DeviceException {
        try {
            Map<String, Object> request = buildRequest(inputId, method, params);
            Map<String, Object> reply = makeRpcCall(request, longTimeout);
            Object result = getResultOrThrow(reply);

            if(result instanceof Map<?,?> map && map.get("http_request") instanceof Map<?,?> httpRequestMap && httpRequestMap.get("params") instanceof Map<?, ?> paramsMap) {
                RpcCallback httpRequestCallback = rpcCallback == null ? new HttpRequest() : rpcCallback;
                Map<String, Object> response = httpRequestCallback.call(paramsMap);
                if(response != null) {
                    return rpc((String)httpRequestMap.get("on-reply"), response, httpRequestCallback, longTimeout);
                }
            }

            return result;
        } catch(JadeResponseException e) {
            log.error("Jade returned an error response", e);
            throw e;
        }
    }

    private Object getResultOrThrow(Map<String, Object> reply) throws DeviceException {
        if(reply.get("error") instanceof Map<?,?> errorMap) {
            throw new JadeResponseException("Jade returned error: " + errorMap.get("message"), (Integer)errorMap.get("code"), (String)errorMap.get("data"));
        }

        return reply.get("result");
    }

    private Map<String, Object> buildRequest(String inputId, String method, Map<String, Object> params) {
        Map<String, Object> request = new HashMap<>();
        request.put("method", method);
        request.put("id", inputId);
        if(params != null && !params.isEmpty()) {
            request.put("params", params);
        }

        return request;
    }

    private Map<String, Object> makeRpcCall(Map<String, Object> request, boolean longTimeout) throws DeviceException {
        assert request.containsKey("id");
        assert request.containsKey("method");
        writeRequest(request);
        Map<String, Object> reply = readResponse(longTimeout);
        validateReply(request, reply);
        return reply;
    }

    private void validateReply(Map<String, Object> request, Map<String, Object> reply) throws DeviceException {
        String requestId = (String)request.get("id");
        String replyId = (String)reply.get("id");

        if(replyId == null) {
            throw new DeviceProtocolException("No replyId in " + reply);
        } else if(replyId.equals("00") && reply.containsKey("error")) {
            //ignore, error response
        } else if(!Objects.equals(requestId, replyId)) {
            throw new DeviceException("Request id of " + requestId + " did not match reply id of " + replyId);
        }
    }

    private void writeRequest(Map<String, Object> request) throws DeviceException {
        byte[] cborMsg = serialiseCborRequest(request);
        int written = 0;
        while(written < cborMsg.length) {
            written += serialPort.writeBytes(cborMsg, cborMsg.length - written, written);
        }
    }

    private byte[] serialiseCborRequest(Map<String, Object> request) throws DeviceException {
        CborBuilder cborBuilder = new CborBuilder();
        MapBuilder<CborBuilder> mapBuilder = cborBuilder.addMap();

        processMap(request, mapBuilder);

        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            new CborEncoder(baos).encode(cborBuilder.build());
            return baos.toByteArray();
        } catch(CborException e) {
            throw new DeviceException("Error encoding CBOR", e);
        }
    }

    @SuppressWarnings("unchecked")
    private static void processMap(Map<String, Object> map, MapBuilder<?> mapBuilder) {
        for(Map.Entry<String, Object> entry : map.entrySet()) {
            String key = entry.getKey();
            Object value = entry.getValue();

            switch(value) {
                case Map<?, ?> nestedMap -> {
                    // If the value is a map, recursively add a nested map
                    MapBuilder<?> nestedMapBuilder = mapBuilder.putMap(key);
                    processMap((Map<String, Object>)nestedMap, nestedMapBuilder);
                    nestedMapBuilder.end();
                }
                case List<?> list -> {
                    // If the value is a list, recursively add the list
                    ArrayBuilder<?> nestedArrayBuilder = mapBuilder.putArray(key);
                    processArray(list, nestedArrayBuilder);
                    nestedArrayBuilder.end();
                }
                case String s -> mapBuilder.put(key, s);
                case Integer i -> mapBuilder.put(key, i);
                case Long l -> mapBuilder.put(key, l);
                case Boolean b -> mapBuilder.put(key, b);
                case Double v -> mapBuilder.put(key, v);
                case byte[] bytes -> mapBuilder.put(key, bytes);
                case null, default -> throw new IllegalArgumentException("Unsupported data type: " + (value == null ? "null" : value.getClass()));
            }
        }
    }

    @SuppressWarnings("unchecked")
    private static void processArray(List<?> list, ArrayBuilder<?> arrayBuilder) {
        for(Object value : list) {
            switch(value) {
                case Map<?, ?> map -> {
                    // If the value is a map, recursively add a nested map
                    MapBuilder<?> nestedMapBuilder = arrayBuilder.addMap();
                    processMap((Map<String, Object>)map, nestedMapBuilder);
                    nestedMapBuilder.end();
                }
                case List<?> nestedList -> {
                    // If the value is a list, recursively add the list
                    ArrayBuilder<?> nestedArrayBuilder = arrayBuilder.addArray();
                    processArray(nestedList, nestedArrayBuilder);
                    nestedArrayBuilder.end();
                }
                case String s -> arrayBuilder.add(s);
                case Integer i -> arrayBuilder.add(i);
                case Long l -> arrayBuilder.add(l);
                case Boolean b -> arrayBuilder.add(b);
                case Double v -> arrayBuilder.add(v);
                case byte[] bytes -> arrayBuilder.add(bytes);
                case null, default -> throw new IllegalArgumentException("Unsupported data type: " + (value == null ? "null" : value.getClass()));
            }
        }
    }

    private Map<String, Object> readResponse(boolean longTimeout) throws DeviceException {
        //Given a 500ms read timeout, try for 2s (or when requiring user interaction, wait for 10m)
        int maxAttempts = longTimeout ? 10 * 60 * 2 : 3;
        for(int attempts = 0; attempts <= maxAttempts; attempts++) {
            try {
                return readCborMessage();
            } catch(SerialPortTimeoutException e) {
                if(attempts == maxAttempts) {
                    throw new DeviceException("Timeout reading response from device. Check the USB connection.", e);
                }
            } catch(IOException e) {
                throw new DeviceException("Error reading response from device. Check the USB connection.", e);
            }
        }

        throw new DeviceException("Timeout reading response from device. Check the USB connection.");
    }

    private Map<String, Object> readCborMessage() throws DeviceException, IOException {
        byte[] cborMsg = null;
        try {
            InputStream in = serialPort.getInputStream();
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte[] readBuffer = new byte[64];
            int numBytes;

            try {
                while((numBytes = in.read(readBuffer)) != -1) {
                    if(numBytes > 0) {
                        baos.write(readBuffer, 0, numBytes);
                    }
                }
            } catch(SerialPortTimeoutException e) {
                if(baos.size() == 0) {
                    throw e;
                }
                //ignore, there is no EOF signal and the Jade can return 0 for bytes available during reading so this 1s timeout represents the actual end of reading
            }

            cborMsg = baos.toByteArray();
            List<DataItem> dataItems = new CborDecoder(new ByteArrayInputStream(cborMsg)).decode();
            for(DataItem dataItem : dataItems) {
                if(dataItem instanceof co.nstant.in.cbor.model.Map dataMap) {
                    if(dataMap.get(new UnicodeString("id")) instanceof UnicodeString) {
                        Map<String, Object> response = new LinkedHashMap<>();
                        convertToMap(dataMap, response);
                        return response;
                    } else if(dataMap.get(new UnicodeString("log")) instanceof UnicodeString logResponse) {
                        String logLevel = logResponse.getString();
                        if(logLevel.length() > 1 && logLevel.charAt(1) == ' ') {
                            switch(logLevel.charAt(0)) {
                                case 'E': log.error(logLevel);
                                case 'W': log.warn(logLevel);
                                case 'I': log.info(logLevel);
                                case 'D': log.debug(logLevel);
                                case 'V': log.trace(logLevel);
                                default: log.error(logLevel);
                            }
                        } else {
                            log.error(logLevel);
                        }
                    }
                } else {
                    log.error("Unhandled message received: " + dataItem);
                }
            }
        } catch(CborException e) {
            String recieved = new String(cborMsg, StandardCharsets.UTF_8);
            if(CharMatcher.ascii().matchesAllOf(recieved)) {
                throw new DeviceException("Error decoding response from device, recieved " + new String(cborMsg, StandardCharsets.UTF_8), e);
            } else {
                throw new DeviceException("Error decoding response from device, recieved " + cborMsg.length + " bytes of " + Utils.bytesToHex(cborMsg), e);
            }
        }

        return Map.of();
    }

    private static void convertToMap(co.nstant.in.cbor.model.Map resultMap, Map<String, Object> result) {
        for(DataItem resultKey : resultMap.getKeys()) {
            if(resultMap.get(resultKey) instanceof UnicodeString resultString) {
                result.put(resultKey.toString(), resultString.getString());
            } else if(resultMap.get(resultKey) instanceof SimpleValue resultValue) {
                result.put(resultKey.toString(), resultValue.getSimpleValueType() == SimpleValueType.TRUE);
            } else if(resultMap.get(resultKey) instanceof Number resultNumber) {
                result.put(resultKey.toString(), resultNumber.getValue().intValue());
            }  else if(resultMap.get(resultKey) instanceof ByteString resultBytes) {
                result.put(resultKey.toString(), resultBytes.getBytes());
            } else if(resultMap.get(resultKey) instanceof co.nstant.in.cbor.model.Map nestedResultMap) {
                Map<String, Object> nestedResult = new LinkedHashMap<>();
                convertToMap(nestedResultMap, nestedResult);
                result.put(resultKey.toString(), nestedResult);
            } else if(resultMap.get(resultKey) instanceof co.nstant.in.cbor.model.Array nestedResultArray) {
                List<Object> nestedResult = new ArrayList<>();
                convertToList(nestedResultArray, nestedResult);
                result.put(resultKey.toString(), nestedResult);
            } else {
                throw new IllegalStateException("Unsupported type: " + resultMap.get(resultKey).getClass());
            }
        }
    }

    private static void convertToList(co.nstant.in.cbor.model.Array resultArray, List<Object> result) {
        for(DataItem resultItem : resultArray.getDataItems()) {
            if(resultItem instanceof UnicodeString resultString) {
                result.add(resultString.getString());
            } else if(resultItem instanceof SimpleValue resultValue) {
                result.add(resultValue.getSimpleValueType() == SimpleValueType.TRUE);
            } else if(resultItem instanceof Number resultNumber) {
                result.add(resultNumber.getValue().intValue());
            } else if(resultItem instanceof ByteString resultBytes) {
                result.add(resultBytes.getBytes());
            } else if(resultItem instanceof co.nstant.in.cbor.model.Map nestedResultMap) {
                Map<String, Object> nestedResult = new LinkedHashMap<>();
                convertToMap(nestedResultMap, nestedResult);
                result.add(nestedResult);
            } else if(resultItem instanceof co.nstant.in.cbor.model.Array nestedResultArray) {
                List<Object> nestedResult = new ArrayList<>();
                convertToList(nestedResultArray, nestedResult);
                result.add(nestedResult);
            } else {
                throw new IllegalStateException("Unsupported type: " + resultItem.getClass());
            }
        }
    }

    @FunctionalInterface
    private static interface RpcCallback {
        public Map<String, Object> call(Map<?, ?> params);
    }

    @SuppressWarnings("unchecked")
    private static class HttpRequest implements RpcCallback {
        @Override
        public Map<String, Object> call(Map<?, ?> params) {
            HttpClientService httpClientService = Lark.getHttpClientService();
            boolean torProxy = httpClientService.getHttpProxySupplier().getHttpProxy(HttpUsage.DEFAULT).isPresent();

            List<String> urls = (List<String>)params.get("urls");
            String url = urls.stream().filter(u -> u.contains(".onion") == torProxy).findFirst().orElse(urls.get(0));

            try {
                IHttpClient httpClient = httpClientService.getHttpClient(HttpUsage.DEFAULT);
                return AsyncUtil.getInstance().blockingGet(httpClient.postJson(url, Map.class, Map.of(), params.get("data"))).get();
            } catch(Exception e) {
                log.error("Error calling " + url, e);
            }

            return null;
        }
    }
}
