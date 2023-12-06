package ch.bt.model;

import ch.bt.model.encryptedindex.EncryptedIndex;
import ch.bt.model.multimap.Ciphertext;

import java.util.Stack;

public record EncryptedIndexWithStash(
        EncryptedIndex encryptedIndex, Stack<Ciphertext> stash) {}
