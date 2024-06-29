package com.example.oauth.utils;

import java.time.ZoneId;
import java.time.ZonedDateTime;

public class TimeUtils {

    public static ZonedDateTime getCurrentTime(){
        return ZonedDateTime.now(ZoneId.of("Asia/Seoul"));
    }
}
