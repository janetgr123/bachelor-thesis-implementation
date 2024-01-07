create table t_network_nodes
(
    pk_node_id integer          not null primary key,
    latitude   double precision not null,
    longitude  double precision not null
);

create table t_check_ins
(
    pk_id     serial primary key,
    latitude  double precision not null,
    longitude double precision not null
);


create table t_spitz
(
    pk_id     serial primary key,
    latitude  double precision not null,
    longitude double precision not null
);



