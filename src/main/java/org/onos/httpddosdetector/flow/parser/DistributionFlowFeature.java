package org.onos.httpddosdetector.flow.parser;

import java.util.ArrayList;

import org.onos.httpddosdetector.Helpers;

/**
 * DistributionFlowFeature
 */
public class DistributionFlowFeature implements IFlowFeature {
    /**
     * Properties
     */
    public long sum;
	public long sumsq;
	public long count;
	public long min;
	public long max;

    public DistributionFlowFeature(long l){
        Set(l);
    }

    @Override 
    public void Add(long l) {
        sum += l;
        sumsq += l * l;
        count++;
        if ((l < min) || (min == 0)) {
            min = l;
        }
        if (l > max) {
            max = l;
        }
    };
    
    @Override 
    public String Export() {
        long stdDev = 0;
        long mean = 0;
        if (count > 0) {
            stdDev = (long) Helpers.stddev((float) sumsq, (float) sum, count);
            mean = sum / count;
        }
        return String.format("%d,%d,%d,%d", min, mean, max, stdDev);
    };

    @Override 
    public long Get() {
        return count;
    };

    @Override 
    public void Set(long l) {
        sum = l;
        sumsq = l * l;
        count = l;
        min = l;
        max = l;
    };

    @Override
    public ArrayList<Long> ToArrayList() {
        ArrayList<Long> array = new ArrayList<Long>();
        long stdDev = 0;
        long mean = 0;
        if (count > 0) {
            stdDev = (long) Helpers.stddev((float) sumsq, (float) sum, count);
            mean = sum / count;
        }
        array.add(min);
        array.add(mean);
        array.add(max);
        array.add(stdDev);
        return array;
    };
}