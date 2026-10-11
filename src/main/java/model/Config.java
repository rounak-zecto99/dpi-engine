package model;

/** Settings used to start the DPI engine. */
public class Config {
    public int numLoadBalancers = 2;
    public int workersPerLoadBalancer = 2;
    public int queueSize = 10_000;
    public String rulesFile = "";
    public boolean verbose = false;

    public Config() { }

    public Config(int numLoadBalancers, int workersPerLoadBalancer) {
        if (numLoadBalancers < 1 || workersPerLoadBalancer < 1) {
            throw new IllegalArgumentException("At least one load balancer and one worker are required");
        }
        this.numLoadBalancers = numLoadBalancers;
        this.workersPerLoadBalancer = workersPerLoadBalancer;
    }
}
