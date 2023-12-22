package ch.bt.model;

import ch.bt.model.searchtoken.SearchToken;

import java.util.List;

public record FromToken(int from, List<SearchToken> token) {}
