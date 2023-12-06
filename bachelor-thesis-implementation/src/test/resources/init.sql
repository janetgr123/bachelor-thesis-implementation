create table t_network_nodes
(
    pk_node_id integer          not null primary key,
    latitude   double precision not null,
    longitude  double precision not null
);

create table t_network_edges
(
    pk_edge_id integer          not null primary key,
    start_node integer          not null,
    end_node   integer          not null,
    distance   double precision not null
);

