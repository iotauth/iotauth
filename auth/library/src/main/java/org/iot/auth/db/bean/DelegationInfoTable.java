package org.iot.auth.db.bean;

import org.json.simple.JSONObject;

import java.sql.ResultSet;
import java.sql.SQLException;


public class DelegationInfoTable {
    public static final String T_DELEGATIONINFO = "delegation_info";

    public enum c {
        ID,
        Parent,
        DelegatedTime,
        RevokedTime
    }
    private long id;
    private long parent;
    private long delegatedTime;
    private long revokedTime;

    public long getId() { return id; }
    public DelegationInfoTable setId(long id) {
        this.id = id;
        return this;
    }

    public long getParent() { return parent; }
    public DelegationInfoTable setParent(long parent) {
        this.parent = parent;
        return this;
    }

    public long getDelegatedTime() { return delegatedTime;}
    public DelegationInfoTable setDelegatedTime(long delegatedTime) {
        this.delegatedTime = delegatedTime;
        return this;
    }

    public long getRevokedTime() { return revokedTime;}
    public DelegationInfoTable setRevokedTime(long revokedTime) {
        this.revokedTime = revokedTime;
        return this;
    }


    @SuppressWarnings("unchecked")
    public JSONObject toJSONObject() {
        JSONObject object = new JSONObject();
        object.put(c.ID.name(), getId());
        object.put(c.Parent.name(), getParent());
        object.put(c.DelegatedTime.name(), getDelegatedTime());
        object.put(c.RevokedTime.name(), getRevokedTime());
        return object;
    }
    public static DelegationInfoTable createRecord(ResultSet resultSet) throws SQLException {
        DelegationInfoTable delegationInfoTable = new DelegationInfoTable();
        delegationInfoTable.setId(resultSet.getLong(c.ID.name()));
        delegationInfoTable.setParent(resultSet.getLong(c.Parent.name()));
        delegationInfoTable.setDelegatedTime(resultSet.getLong(c.DelegatedTime.name()));
        delegationInfoTable.setRevokedTime(resultSet.getLong(c.RevokedTime.name()));
        return delegationInfoTable;
    }
}
