package org.iot.auth.db.bean;

import org.json.simple.JSONObject;

import java.sql.ResultSet;
import java.sql.SQLException;


public class AgentTable {
    public static final String T_Agent = "agent_info";

    public enum c {
        User,
        Agent,
        AgentLevel
    }
    private String user;
    private String agent;
    private String agentLevel;

    public String getUser() {
        return user;
    }
    public void setUser(String user) {
        this.user = user;
    }

    public String getAgent() {
        return agent;
    }

    public void setAgent(String agent) {
        this.agent = agent;
    }

    public String getAgentLevel() {
        return agentLevel;
    }

    public void setAgentLevel(String agentLevel) {
        this.agentLevel = agentLevel;
    }
    @SuppressWarnings("unchecked")
    public JSONObject toJSONObject() {
        JSONObject object = new JSONObject();
        object.put(c.User.name(), getUser());
        object.put(c.Agent.name(), getAgent());
        object.put(c.AgentLevel.name(), getAgentLevel());
        return object;
    }
    public static AgentTable createRecord(ResultSet resultSet) throws SQLException {
        AgentTable Agent = new AgentTable();
        Agent.setUser(resultSet.getString(c.User.name()));
        Agent.setAgent(resultSet.getString(c.Agent.name()));
        Agent.setAgentLevel(resultSet.getString(c.AgentLevel.name()));
        return Agent;
    }
}
