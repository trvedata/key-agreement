package org.trvedata.sgm;

public enum Operation {
    MESSAGE("message"),
    ADD("add"),
    REMOVE("remove"),
    UPDATE("update");

    public final String opcode;

    Operation(String opcode) {
        this.opcode = opcode;
    }
}
