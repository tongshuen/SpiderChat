package com.spider.minecraft.util;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * JSON 编解码工具 — 与 Spider 协议兼容的消息信封格式。
 */
public final class JsonUtil {

    private static final Gson GSON = new GsonBuilder()
            .disableHtmlEscaping()
            .create();

    private JsonUtil() {}

    public static Gson gson() {
        return GSON;
    }

    public static String toJson(Object obj) {
        return GSON.toJson(obj);
    }

    public static JsonObject parse(String json) {
        return JsonParser.parseString(json).getAsJsonObject();
    }

    public static <T> T fromJson(String json, Class<T> clazz) {
        return GSON.fromJson(json, clazz);
    }

    public static String b64Encode(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    public static byte[] b64Decode(String b64) {
        return Base64.getDecoder().decode(b64);
    }

    public static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    public static String fromUtf8(byte[] data) {
        return new String(data, StandardCharsets.UTF_8);
    }
}
