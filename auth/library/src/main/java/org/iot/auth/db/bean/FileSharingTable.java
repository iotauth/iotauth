package org.iot.auth.db.bean;

import org.json.simple.JSONObject;

import java.sql.ResultSet;
import java.sql.SQLException;


public class FileSharingTable {
    public static final String T_File_Sharing = "file_sharing_info";

    public enum c {
        Owner,
        Reader
    }
    private String owner;
    private String reader;

    public String getOwner() {
        return owner;
    }
    public void setOwner(String owner) {
        this.owner = owner;
    }

    public String getReader() {
        return reader;
    }

    public void setReader(String reader) {
        this.reader = reader;
    }

    @SuppressWarnings("unchecked")
    public JSONObject toJSONObject() {
        JSONObject object = new JSONObject();
        object.put(c.Owner.name(), getOwner());
        object.put(c.Reader.name(), getReader());
        return object;
    }
    public static FileSharingTable createRecord(ResultSet resultSet) throws SQLException {
        FileSharingTable FileSharing = new FileSharingTable();
        FileSharing.setOwner(resultSet.getString(c.Owner.name()));
        FileSharing.setReader(resultSet.getString(c.Reader.name()));
        return FileSharing;
    }
}
