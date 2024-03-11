package ch.bt.model.searchtoken;

public record SearchTokenBytesKeys(SearchTokenBytes tokenBytes, SearchTokenKeys tokenKeys)
        implements SearchToken {}
