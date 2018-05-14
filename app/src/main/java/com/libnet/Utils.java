package com.libnet;

import android.content.Context;

import java.util.Map;

/**
 * Created by jianqiu on 5/11/18.
 */
public class Utils {

    static {
        System.loadLibrary("sign");
    }

    public native static String getSign(Context context, Map<String, String> params);

}
