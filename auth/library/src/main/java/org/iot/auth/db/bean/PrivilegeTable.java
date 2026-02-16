package org.iot.auth.db.bean;

import org.json.simple.JSONObject;

import java.sql.ResultSet;
import java.sql.SQLException;


public class PrivilegeTable {
    public static final String T_PRIVILEGE = "privilege";

    public enum c {
        PrivilegeType,
        PrivilegedEntity,
        Subject,
        Object,
        Validity,
        Info
    }
    private String privilegeType;
    private String privilegedEntity;
    private String subject;
    private String object;
    private String validity;
    private String info;
    // TODO-SY set info as JSON object as {"cryptoSpec":"AES-128-CBC:SHA256","absValidity": "1*day","relValidity": "1*hour"}

    public String getPrivilegeType() {
        return privilegeType;
    }
    public void setPrivilegeType(String privilegeType) {
        this.privilegeType = privilegeType;
    }

    public String getPrivilegedEntity() {
        return privilegedEntity;
    }
    public void setPrivilegedEntity(String privilegedEntity) {
        this.privilegedEntity = privilegedEntity;
    }

    public String getSubject() { return subject;}
    public void setSubject(String subject) {
        this.subject = subject;
    }

    public String getObject() {
        return object;
    }
    public void setObject(String object) {
        this.object = object;
    }

    public String getValidity() {
        return validity;
    }
    public void setValidity(String validity) {
        this.validity = validity;
    }

    public String getInfo() {
        return info;
    }
    public void setInfo(String info) { this.info = info;}


    @SuppressWarnings("unchecked")
    public JSONObject toJSONObject() {
        JSONObject object = new JSONObject();
        object.put(c.PrivilegeType.name(), getPrivilegeType());
        object.put(c.PrivilegedEntity.name(), getPrivilegedEntity());
        object.put(c.Subject.name(), getSubject());
        object.put(c.Object.name(), getObject());
        object.put(c.Validity.name(), getValidity());
        object.put(c.Info.name(), getInfo());
        return object;
    }
    public static PrivilegeTable createRecord(ResultSet resultSet) throws SQLException {
        PrivilegeTable Privilege = new PrivilegeTable();
        Privilege.setPrivilegeType(resultSet.getString(c.PrivilegeType.name()));
        Privilege.setPrivilegedEntity(resultSet.getString(c.PrivilegedEntity.name()));
        Privilege.setSubject(resultSet.getString(c.Subject.name()));
        Privilege.setObject(resultSet.getString(c.Object.name()));
        Privilege.setValidity(resultSet.getString(c.Validity.name()));
        Privilege.setInfo(resultSet.getString(c.Info.name()));
        return Privilege;
    }
}
