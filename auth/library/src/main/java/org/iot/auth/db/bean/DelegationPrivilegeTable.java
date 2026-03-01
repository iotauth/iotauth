package org.iot.auth.db.bean;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import java.sql.ResultSet;
import java.sql.SQLException;


public class DelegationPrivilegeTable {
    public static final String T_DELEGATION_PRIVILEGE = "delegation_privilege";

    public enum c {
        PrivilegeType,
        PrivilegedGroup,
        Subject,
        Object,
        Validity,
        Info
    }
    private String privilegeType;
    private String privilegedGroup;
    private String subject;
    private String object;
    private String validity;
    private JSONObject info;

    public String getPrivilegeType() {
        return privilegeType;
    }
    public void setPrivilegeType(String privilegeType) {
        this.privilegeType = privilegeType;
    }

    public String getPrivilegedGroup() {
        return privilegedGroup;
    }
    public void setprivilegedGroup(String privilegedGroup) {
        this.privilegedGroup = privilegedGroup;
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

    public JSONObject getInfo() {
        return info;
    }
    public void setInfo(String info) {
        try {
            this.info = (JSONObject) new JSONParser().parse(info);
        } catch (ParseException e) {
            throw new IllegalArgumentException("Invalid JSON in Info column: " + info, e);
        }
    }


    @SuppressWarnings("unchecked")
    public JSONObject toJSONObject() {
        JSONObject object = new JSONObject();
        object.put(c.PrivilegeType.name(), getPrivilegeType());
        object.put(c.PrivilegedGroup.name(), getPrivilegedGroup());
        object.put(c.Subject.name(), getSubject());
        object.put(c.Object.name(), getObject());
        object.put(c.Validity.name(), getValidity());
        object.put(c.Info.name(), getInfo());
        return object;
    }
    public static DelegationPrivilegeTable createRecord(ResultSet resultSet) throws SQLException, ParseException {
        DelegationPrivilegeTable delegationPrivilegeTable = new DelegationPrivilegeTable();
        delegationPrivilegeTable.setPrivilegeType(resultSet.getString(c.PrivilegeType.name()));
        delegationPrivilegeTable.setprivilegedGroup(resultSet.getString(c.PrivilegedGroup.name()));
        delegationPrivilegeTable.setSubject(resultSet.getString(c.Subject.name()));
        delegationPrivilegeTable.setObject(resultSet.getString(c.Object.name()));
        delegationPrivilegeTable.setValidity(resultSet.getString(c.Validity.name()));
        delegationPrivilegeTable.setInfo(resultSet.getString(c.Info.name()));
        return delegationPrivilegeTable;

    }
}
