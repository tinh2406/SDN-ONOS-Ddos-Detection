package org.onos.httpddosdetector.flow.parser;

import java.util.ArrayList;

/**
 * ValueFlowFeature
 */
public class ValueFlowFeature implements IFlowFeature {
    /**
     * Properties
     */
    public long value;

    public ValueFlowFeature(long l){
        Set(l);
    }

    @Override 
    public void Add(long l) {
        value += l;
    };
    
    @Override 
    public String Export() {
        return String.format("%d", value);
    };

    @Override 
    public long Get() {
        return value;
    };

    @Override 
    public void Set(long l) {
        value = l;
    };

    @Override
    public ArrayList<Long> ToArrayList() {
        ArrayList<Long> array = new ArrayList<Long>();
        array.add(value);
        return array;
    };
}