package ch.bt.model;

import ch.bt.model.encryptedindex.EncryptedIndex;
import ch.bt.model.multimap.Ciphertext;

import java.util.Stack;

/**
 * This record encapsulated the encrypted index, its number of dummy entries, and the stash used for
 * Cuckoo Hashing
 *
 * @param encryptedIndex the encrypted index
 * @param stash the stash
 * @param numberOfDummyValues the number of dummy entries in the encrypted index
 * @author Janet Greutmann
 */
public record EncryptedIndexWithStash(
        EncryptedIndex encryptedIndex, Stack<Ciphertext> stash, int numberOfDummyValues) {}
