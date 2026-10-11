import core.DPIEngine;
import model.Config;

/** Command-line entry point for the DPI engine. */
public class Main {
    private static void printUsage() {
        System.out.println("Usage: java Main <input.pcap> <output.pcap> [options]");
        System.out.println("Options:");
        System.out.println("  --block-ip=1.2.3.4       Block packets involving this IP");
        System.out.println("  --block-domain=example.com  Block this domain and its subdomains");
        System.out.println("  --block-app=Google       Block traffic classified as this app");
        System.out.println("  --block-port=443         Block traffic using this port");
        System.out.println("  --rules=rules.txt        Load rules from a text file");
        System.out.println("  --lbs=2                  Number of load balancers (default 2)");
        System.out.println("  --workers=2              Workers per load balancer (default 2)");
    }

    public static void main(String[] args) {
        if (args.length < 2 || "--help".equals(args[0])) {
            printUsage();
            return;
        }

        String inputFile = args[0];
        String outputFile = args[1];
        Config config = new Config();
        for (int i = 2; i < args.length; i++) {
            if (args[i].startsWith("--rules=")) config.rulesFile = value(args[i]);
            else if (args[i].startsWith("--lbs=")) config.numLoadBalancers = Integer.parseInt(value(args[i]));
            else if (args[i].startsWith("--workers=")) config.workersPerLoadBalancer = Integer.parseInt(value(args[i]));
        }

        DPIEngine engine = new DPIEngine(config);
        if (!engine.initialize()) return;

        for (int i = 2; i < args.length; i++) {
            try {
                if (args[i].startsWith("--block-ip=")) engine.blockIP(value(args[i]));
                else if (args[i].startsWith("--block-domain=")) engine.blockDomain(value(args[i]));
                else if (args[i].startsWith("--block-app=")) engine.blockApp(value(args[i]));
                else if (args[i].startsWith("--block-port=")) engine.blockPort(Integer.parseInt(value(args[i])));
            } catch (IllegalArgumentException e) {
                System.err.println("Invalid option '" + args[i] + "': " + e.getMessage());
                return;
            }
        }

        if (!engine.processFile(inputFile, outputFile)) {
            System.err.println("DPI processing failed.");
        }
    }

    private static String value(String option) {
        return option.substring(option.indexOf('=') + 1);
    }
}
