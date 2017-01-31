package com.example.hokeunkim.myapplication;

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothSocket;
import android.content.Intent;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Set;
import java.util.UUID;

public class MainActivity extends AppCompatActivity {

    BluetoothAdapter mBluetoothAdapter = BluetoothAdapter.getDefaultAdapter();
    private static final String TAG = "MY_APP_DEBUG_TAG";
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        if (mBluetoothAdapter == null) {
            // Device does not support Bluetooth
        }
        int REQUEST_ENABLE_BT = 2;
        if (!mBluetoothAdapter.isEnabled()) {
            Intent enableBtIntent = new Intent(BluetoothAdapter.ACTION_REQUEST_ENABLE);
            startActivityForResult(enableBtIntent, REQUEST_ENABLE_BT);
        }
        Set<BluetoothDevice> pairedDevices = mBluetoothAdapter.getBondedDevices();

        if (pairedDevices.size() > 0) {
            // There are paired devices. Get the name and address of each paired device.
            for (BluetoothDevice device : pairedDevices) {
                String deviceName = device.getName();
                String deviceHardwareAddress = device.getAddress(); // MAC address
                System.out.println("deviceName: " + deviceName);

                ConnectThread connectThread = new ConnectThread(device);
                connectThread.start();
            }
        }
    }

    UUID MY_UUID = UUID.fromString("d0c722b0-7e15-11e1-b0c4-0800200c9a66");

    private class ConnectThread extends Thread {
        private final BluetoothSocket mmSocket;
        private final BluetoothDevice mmDevice;

        public ConnectThread(BluetoothDevice device) {
            // Use a temporary object that is later assigned to mmSocket
            // because mmSocket is final.
            BluetoothSocket tmp = null;
            mmDevice = device;

            try {
                // Get a BluetoothSocket to connect with the given BluetoothDevice.
                // MY_UUID is the app's UUID string, also used in the server code.
                tmp = device.createRfcommSocketToServiceRecord(MY_UUID);
            } catch (IOException e) {
                System.out.println("Error occurred??");
                Log.e(TAG, "Socket's create() method failed", e);
            }
            mmSocket = tmp;
        }

        public void run() {
            // Cancel discovery because it otherwise slows down the connection.
            mBluetoothAdapter.cancelDiscovery();

            System.out.println("In run()");
            try {
                // Connect to the remote device through the socket. This call blocks
                // until it succeeds or throws an exception.
                mmSocket.connect();
            } catch (IOException connectException) {
                // Unable to connect; close the socket and return.

                System.out.println("Exception: " + connectException.getMessage());
                try {
                    mmSocket.close();
                } catch (IOException closeException) {
                    Log.e(TAG, "Could not close the client socket", closeException);
                }
                return;
            }
            try {
                OutputStream os = mmSocket.getOutputStream();
                String data = "hello world Auth! hello world Auth! hello world Auth! hello world Auth! " +
                        "hello world Auth! hello world Auth! hello world Auth! hello world Auth! " +
                        "hello world Auth! hello world Auth! hello world Auth! hello world Auth! " +
                        "hello world Auth! hello world Auth! hello world Auth! hello world Auth! " +
                        "hello world Auth! hello world Auth! hello world Auth! hello world Auth! " +
                        "hello world Auth! hello world Auth! hello world Auth! hello world Auth! " +
                        "hello world Auth! hello world Auth! hello world Auth! hello world Auth! " +
                        "hello world Auth! hello world Auth! hello world Auth! hello world Auth! " +
                        "hello world Auth! hello world Auth! hello world Auth! hello world Auth! " +
                        "hello world Auth! hello world Auth! hello world Auth! hello world Auth! " +
                        "hello world Auth! hello world Auth! hello world Auth! hello world Auth! " +
                        "hello world Auth! hello world Auth! hello world Auth! hello world Auth! " +
                        "hello world Auth! hello world Auth! hello world Auth! hello world Auth! " +
                        "hello world Auth! hello world Auth! hello world Auth! hello world Auth! " +
                        "hello world Auth! hello world Auth! hello world Auth! hello world Auth! " +
                        "hello world Auth! hello world Auth! hello world Auth! hello world Auth! " +
                        "hello world Auth! hello world Auth! hello world Auth! hello world Auth! " +
                        "hello world Auth! hello world Auth! hello world Auth! hello world Auth! " +
                        "hello world Auth! hello world Auth! hello world Auth! hello world Auth! " +
                        "hello world Auth! hello world Auth! hello world Auth! hello world Auth! " +
                        "hello world Auth! hello world Auth! hello world Auth! hello world Auth! " +
                        "hello world Auth! hello world Auth! hello world Auth! hello world Auth! " +
                        "hello world Auth! hello world Auth! hello world Auth! hello world Auth! " +
                        "hello world Auth! hello world Auth! hello world Auth! hello world Auth! " +
                        "hello world Auth! hello world Auth! hello world Auth! hello world Auth! " +
                        "hello world Auth! hello world Auth! hello world Auth! hello world Auth! " +
                        "hello world Auth! hello world Auth! hello world Auth! hello world Auth! " +
                        "hello world Auth! hello world Auth! hello world Auth! hello world Auth! " +
                        "hello world Auth! hello world Auth! hello world Auth! hello world Auth! " +
                        "hello world Auth! hello world Auth! hello world Auth! hello world Auth! " +
                        "hello world Auth! hello world Auth! hello world Auth! hello world Auth! " +
                        "hello world Auth! hello world Auth! hello world Auth! hello world Auth! " +
                        "hello world Auth! hello world Auth! hello world Auth! hello world Auth! " +
                        "hello world Auth! hello world Auth! hello world Auth! hello world Auth! " +
                        "hello world Auth! hello world Auth! hello world Auth! hello world Auth! " +
                        "hello world Auth! hello world Auth! hello world Auth! hello world Auth! " +
                        "hello world Auth! hello world Auth! hello world Auth! hello world Auth! " +
                        "hello world Auth! hello world Auth! hello world Auth! hello world Auth! " +
                        "hello world Auth! hello world Auth! hello world Auth! hello world Auth! " +
                        "hello world Auth! hello world Auth! hello world Auth! hello world Auth! " +
                        "hello world Auth! hello world Auth! hello world Auth! hello world Auth! " +
                        "hello world Auth! hello world Auth! hello world Auth! hello world Auth! " +
                        "hello world Auth! hello world Auth! hello world Auth! hello world Auth! " +
                        "hello world Auth! hello world Auth! hello world Auth! hello world Auth! " +
                        "hello world Auth! hello world Auth! hello world Auth! hello world Auth! " +
                        "hello world Auth! hello world Auth! hello world Auth! hello world Auth! " +
                        "hello world Auth! hello world Auth! hello world Auth! hello world Auth! " +
                        "hello world Auth! hello world Auth! hello world Auth! hello world Auth! " +
                        "hello world Auth! hello world Auth! hello world Auth! hello world Auth! " +
                        "hello world Auth! hello world Auth!";
                System.out.println("data length:" + data.length());
                os.write(data.getBytes());
            } catch (IOException e) {
                e.printStackTrace();
            }

            // The connection attempt succeeded. Perform work associated with
            // the connection in a separate thread.
            //manageMyConnectedSocket(mmSocket);
        }

        // Closes the client socket and causes the thread to finish.
        public void cancel() {
            try {
                mmSocket.close();
            } catch (IOException e) {
                Log.e(TAG, "Could not close the client socket", e);
            }
        }
    }
}
