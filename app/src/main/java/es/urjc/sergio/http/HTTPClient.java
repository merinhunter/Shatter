package es.urjc.sergio.http;

import android.os.AsyncTask;
import android.util.Log;

import org.apache.commons.io.IOUtils;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;

import es.urjc.sergio.common.ExternalStorage;
import es.urjc.sergio.common.FileIO;

public class HTTPClient {
    private final String TAG = "HTTPClient";

    public void getIndex(String sessionID) throws Exception {
        String SERVER_IP = "http://192.168.1.20:8080/";
        String url = SERVER_IP + sessionID;

        HttpGetRequest getRequest = new HttpGetRequest();

        byte[] index = getRequest.execute(url).get();

        if (index == null) {
            Log.d(TAG, "Index is null");
            throw new Exception("Index missing");
        }

        String indexPath = ExternalStorage.getFilePath(FileIO.appPath + sessionID + '/' + FileIO.indexFile);
        FileIO.write(index, indexPath);
    }

    public void getFile(String url, String tmpPath) throws Exception {
        String filename = url.substring(url.lastIndexOf('/') + 1);
        Log.d(TAG, "Getting " + url);

        HttpGetRequest getRequest = new HttpGetRequest();

        byte[] file = getRequest.execute(url).get();

        if (file == null) {
            Log.e(TAG, url + " is null");
            throw new Exception(url + " missing");
        }

        String filePath = tmpPath + filename;
        FileIO.write(file, filePath);
    }

    public static class HttpGetRequest extends AsyncTask<String, Void, byte[]> {
        static final String REQUEST_METHOD = "GET";
        static final int READ_TIMEOUT = 15000;
        static final int CONNECTION_TIMEOUT = 15000;

        @Override
        protected byte[] doInBackground(String... params) {
            String stringUrl = params[0];
            byte[] result;

            try {
                URL url = new URL(stringUrl);

                HttpURLConnection connection = (HttpURLConnection)
                        url.openConnection();

                connection.setRequestMethod(REQUEST_METHOD);
                connection.setReadTimeout(READ_TIMEOUT);
                connection.setConnectTimeout(CONNECTION_TIMEOUT);

                connection.connect();

                result = IOUtils.toByteArray(connection.getInputStream());
            } catch (IOException e) {
                e.printStackTrace();
                result = null;
            }

            return result;
        }

        @Override
        protected void onPostExecute(byte[] result) {
            super.onPostExecute(result);
        }
    }
}
