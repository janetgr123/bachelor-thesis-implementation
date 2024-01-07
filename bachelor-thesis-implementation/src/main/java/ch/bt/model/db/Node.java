package ch.bt.model.db;

/**
 * This record encapsulates the data of the used dataset.
 *
 * @param id the id of the node
 * @param latitude the latitude of the node
 * @param longitude the longitude of the node
 * @author Janet Greutmann
 */
public record Node(int id, double latitude, double longitude) {}
