package org.iot.auth.db.bean;

import org.json.simple.JSONObject;

import java.sql.ResultSet;
import java.sql.SQLException;


public class FileSharingTable {
    public static final String T_File_Sharing = "file_sharing_info";

    public enum c {
        Owner,
        Name
    }
    private String owner;
    private String name;

    public String getOwner() {
        return owner;
    }
    public void setOwner(String owner) {
        this.owner = owner;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    @SuppressWarnings("unchecked")
    public JSONObject toJSONObject() {
        JSONObject object = new JSONObject();
        object.put(c.Owner.name(), getOwner());
        object.put(c.Name.name(), getName());
        return object;
    }
    public static FileSharingTable createRecord(ResultSet resultSet) throws SQLException {
        FileSharingTable FileSharing = new FileSharingTable();
        FileSharing.setOwner(resultSet.getString(c.Owner.name()));
        FileSharing.setName(resultSet.getString(c.Name.name()));
        return FileSharing;
    }
}
