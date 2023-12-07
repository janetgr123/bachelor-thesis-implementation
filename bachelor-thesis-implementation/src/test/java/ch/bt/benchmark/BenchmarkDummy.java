package ch.bt.benchmark;

import org.openjdk.jmh.annotations.*;

import java.util.concurrent.TimeUnit;

public class BenchmarkDummy {

    @Benchmark
    @Fork(value = 1, warmups = 2)
    @OutputTimeUnit(TimeUnit.NANOSECONDS)
    @BenchmarkMode(Mode.AverageTime)
    public void someMethod(){

    }
}
