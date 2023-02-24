package ru.rudakov.smartlockserver.util;

import lombok.Getter;

import java.util.Date;

public class ErrorMessage {
    @Getter
    private int statusCode;
    @Getter
    private Date timestamp;
    @Getter
    private String message;
    @Getter
    private String description;

    public ErrorMessage(int statusCode, Date timestamp, String message, String description) {
        this.statusCode = statusCode;
        this.timestamp = timestamp;
        this.message = message;
        this.description = description;
    }
}