package org.iot.auth.androidauth;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import org.iot.auth.AuthServer;
import org.iot.auth.config.AuthServerProperties;

import java.io.IOException;


public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        String propertiesFilePath = "properties";
        try {
            System.out.println("We're gonna do something!");
            AuthServerProperties properties = new AuthServerProperties(propertiesFilePath);
            AuthServer authServer = new AuthServer(properties);
        }
        catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }
}
