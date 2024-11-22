package org.onos.httpddosdetector.flow.parser;

import java.util.ArrayList;

/**
 * Defines the minimum set of functions needed for a FlowFeature.
 */
public interface IFlowFeature {
    /**
     * Add a particular value to a feature
     *
     * @param l the long int to be added to the feature
     */
    void Add(long l);

    /**
     * Export the contents of a feature in string form
     *
     * @return comma separeted string of the feature values
     */
    String Export();
    
    /**
     * Export the contents of a feature in an array form
     *
     * @return array list containing the components values
     */
    ArrayList<Long> ToArrayList();

    /**
     * Gets the first bin element
     *
     * @return long the first bin element
     */
	long Get();

    /**
     * Reset the feature to a particular value
     *
     * @param l the long int to set to the feature
     */
    void Set(long l);
}