package com.codejam.codex.authzen.constants;

public enum AppConstant {
    USER("user"),
    AUTH("auth"),
    ADMIN("admin");

    private final String value;

    AppConstant(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}