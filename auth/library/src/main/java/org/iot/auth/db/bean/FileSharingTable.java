package org.iot.auth.db.bean;

import org.json.simple.JSONObject;

import java.sql.ResultSet;
import java.sql.SQLException;


public class FileSharingTable {
    public static final String T_File_Sharing = "file_sharing_info";

    public enum c {
        Owner,
        Reader,
        ReaderType
    }
    private String owner;
    private String reader;
    private String readerType;

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

    public String getReaderType() {
        return readerType;
    }

    public void setReaderType(String readerType) {
        this.readerType = readerType;
    }
    @SuppressWarnings("unchecked")
    public JSONObject toJSONObject() {
        JSONObject object = new JSONObject();
        object.put(c.Owner.name(), getOwner());
        object.put(c.Reader.name(), getReader());
        object.put(c.ReaderType.name(), getReaderType());
        return object;
    }
    public static FileSharingTable createRecord(ResultSet resultSet) throws SQLException {
        FileSharingTable FileSharing = new FileSharingTable();
        FileSharing.setOwner(resultSet.getString(c.Owner.name()));
        FileSharing.setReader(resultSet.getString(c.Reader.name()));
        FileSharing.setReaderType(resultSet.getString(c.ReaderType.name()));
        return FileSharing;
    }
}
