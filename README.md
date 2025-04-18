# AWS VPC Flow Log Detections Mod for Powerpipe

[Tailpipe](https://tailpipe.io) is an open-source CLI tool that allows you to collect logs and query them with SQL.

[AWS](https://aws.amazon.com/) provides on-demand cloud computing platforms and APIs to authenticated customers on a metered pay-as-you-go basis.

The [AWS VPC Flow Log Detections Mod](https://hub.powerpipe.io/mods/turbot/tailpipe-mod-aws-vpc-flow-log-detections) contains pre-built dashboards and detections, which can be used to monitor and analyze network activity across your AWS accounts.

Run detection benchmarks:
![image](docs/images/aws_vpc_flow_log_mitre_dashboard.png)

View insights in dashboards:
![image](docs/images/aws_vpc_flow_log_activity_dashboard.png)

## Documentation

- **[Benchmarks and Detections →](https://hub.powerpipe.io/mods/turbot/aws-vpc-flow-log-detections/benchmarks)**

## Getting Started

Install Powerpipe from the [downloads page](https://powerpipe.io/downloads):

```bash
# macOS
brew install turbot/tap/powerpipe

# Linux or Windows (WSL)
sudo /bin/sh -c "$(curl -fsSL https://powerpipe.io/install/powerpipe.sh)"
```

This mod also requires AWS VPC flow logs to be collected using Tailpipe with the AWS plugin:
- [Get started with the AWS plugin for Tailpipe →](https://tailpipe.io/plugins/turbot/aws)

Install the mod:

```bash
mkdir dashboards
cd dashboards
powerpipe mod install github.com/turbot/tailpipe-mod-aws-vpc-flow-log-detections
```

### Browsing Dashboards

Start the dashboard server:

```bash
powerpipe server
```

Browse and view your dashboards at **http://localhost:9033**.

### Running Benchmarks in Your Terminal

Instead of running benchmarks in a dashboard, you can also run them within your terminal with the `powerpipe benchmark` command:

List available benchmarks:

```bash
powerpipe benchmark list
```

Run a benchmark:

```bash
powerpipe benchmark run aws_vpc_flow_log_detections.benchmark.mitre_attack_v161
```

Different output formats are also available, for more information please see [Output Formats](https://powerpipe.io/docs/reference/cli/benchmark#output-formats).

## Open Source & Contributing

This repository is published under the [Apache 2.0 license](LICENSE). Please see our [code of conduct](https://github.com/turbot/.github/blob/main/CODE_OF_CONDUCT.md). We look forward to collaborating with you!

[Tailpipe](https://tailpipe.io) and [Powerpipe](https://powerpipe.io) are products produced from this open source software, exclusively by [Turbot HQ, Inc](https://turbot.com). They are distributed under our commercial terms. Others are allowed to make their own distribution of the software, but cannot use any of the Turbot trademarks, cloud services, etc. You can learn more in our [Open Source FAQ](https://turbot.com/open-source).

## Get Involved

**[Join #tailpipe and #powerpipe on Slack →](https://turbot.com/community/join)**

Want to help but don't know where to start? Pick up one of the `help wanted` issues:

- [Powerpipe](https://github.com/turbot/powerpipe/labels/help%20wanted)
- [Tailpipe](https://github.com/turbot/tailpipe/labels/help%20wanted)
- [AWS VPC Flow Log Detections Mod](https://github.com/turbot/tailpipe-mod-aws-vpc-flow-log-detections/labels/help%20wanted)
