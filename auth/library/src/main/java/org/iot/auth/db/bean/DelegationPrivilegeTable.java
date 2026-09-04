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
        SubjectGroup,
        ObjectGroup,
        Validity,
        Info
    }
    private String privilegeType;
    private String privilegedGroup;
    private String subjectGroup;
    private String objectGroup;
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

    public String getSubjectGroup() { return subjectGroup;}
    public void setSubjectGroup(String subjectGroup) {
        this.subjectGroup = subjectGroup;
    }

    public String getObjectGroup() {
        return objectGroup;
    }
    public void setObjectGroup(String objectGroup) {
        this.objectGroup = objectGroup;
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
        object.put(c.SubjectGroup.name(), getSubjectGroup());
        object.put(c.ObjectGroup.name(), getObjectGroup());
        object.put(c.Validity.name(), getValidity());
        object.put(c.Info.name(), getInfo());
        return object;
    }
    public static DelegationPrivilegeTable createRecord(ResultSet resultSet) throws SQLException, ParseException {
        DelegationPrivilegeTable delegationPrivilegeTable = new DelegationPrivilegeTable();
        delegationPrivilegeTable.setPrivilegeType(resultSet.getString(c.PrivilegeType.name()));
        delegationPrivilegeTable.setprivilegedGroup(resultSet.getString(c.PrivilegedGroup.name()));
        delegationPrivilegeTable.setSubjectGroup(resultSet.getString(c.SubjectGroup.name()));
        delegationPrivilegeTable.setObjectGroup(resultSet.getString(c.ObjectGroup.name()));
        delegationPrivilegeTable.setValidity(resultSet.getString(c.Validity.name()));
        delegationPrivilegeTable.setInfo(resultSet.getString(c.Info.name()));
        return delegationPrivilegeTable;

    }
}
