import { describe, expect, test } from "@/test";
import type { EffectiveNetworkPolicy } from "@/types";
import {
  buildManagedNetworkPolicy,
  constructManagedNetworkPolicyName,
  shouldManageK8sNetworkPolicy,
} from "./network-policy";

describe("managed MCP Kubernetes NetworkPolicy", () => {
  test("builds a deny-all egress policy for egress off", () => {
    const manifest = buildManagedNetworkPolicy({
      name: "mcp-egress-test",
      podSelectorLabels: {
        app: "mcp-server",
        "mcp-server-id": "server-id",
      },
      effectivePolicy: makeEffectivePolicy({ egressMode: "off" }),
    });

    expect(manifest).toMatchObject({
      apiVersion: "networking.k8s.io/v1",
      kind: "NetworkPolicy",
      metadata: {
        name: "mcp-egress-test",
        annotations: {
          "archestra.io/network-policy-egress-mode": "off",
          "archestra.io/network-policy-domain-enforcement":
            "not-supported-by-kubernetes-networkpolicy",
        },
      },
      spec: {
        podSelector: {
          matchLabels: {
            app: "mcp-server",
            "mcp-server-id": "server-id",
          },
        },
        policyTypes: ["Egress"],
        egress: [],
      },
    });
  });

  test("builds a restricted policy that fails closed except DNS", () => {
    const manifest = buildManagedNetworkPolicy({
      name: "mcp-egress-test",
      podSelectorLabels: {
        app: "mcp-server",
        "mcp-server-id": "server-id",
      },
      effectivePolicy: makeEffectivePolicy({
        egressMode: "restricted",
        allowedDomains: ["registry.npmjs.org"],
        allowedHttpMethods: "read_only",
      }),
    });

    expect(manifest.spec?.egress).toEqual([
      {
        to: [
          {
            namespaceSelector: {
              matchLabels: {
                "kubernetes.io/metadata.name": "kube-system",
              },
            },
            podSelector: {
              matchLabels: {
                "k8s-app": "kube-dns",
              },
            },
          },
        ],
        ports: [
          { protocol: "UDP", port: 53 },
          { protocol: "TCP", port: 53 },
        ],
      },
    ]);
    expect(manifest.metadata?.annotations).toMatchObject({
      "archestra.io/network-policy-allowed-domains": "registry.npmjs.org",
      "archestra.io/network-policy-allowed-http-methods": "read_only",
      "archestra.io/network-policy-domain-enforcement":
        "not-supported-by-kubernetes-networkpolicy",
      "archestra.io/network-policy-http-method-enforcement":
        "not-supported-by-kubernetes-networkpolicy",
    });
  });

  test("does not manage a Kubernetes NetworkPolicy for unrestricted or built-in policy", () => {
    expect(
      shouldManageK8sNetworkPolicy(makeEffectivePolicy({ egressMode: "off" })),
    ).toBe(true);
    expect(
      shouldManageK8sNetworkPolicy(
        makeEffectivePolicy({ egressMode: "restricted" }),
      ),
    ).toBe(true);
    expect(
      shouldManageK8sNetworkPolicy(
        makeEffectivePolicy({ egressMode: "unrestricted" }),
      ),
    ).toBe(false);
    expect(
      shouldManageK8sNetworkPolicy({ source: "built_in", policy: null }),
    ).toBe(false);
  });

  test("constructs a DNS-safe managed policy name", () => {
    expect(constructManagedNetworkPolicyName("mcp.Test.Server")).toBe(
      "mcp-egress-mcp-Test-Server".toLowerCase(),
    );
  });
});

function makeEffectivePolicy(
  overrides: Partial<NonNullable<EffectiveNetworkPolicy["policy"]>>,
): EffectiveNetworkPolicy {
  return {
    source: "environment",
    policy: {
      id: "policy-id",
      organizationId: "org-id",
      name: "Test policy",
      description: null,
      egressMode: "restricted",
      domainPreset: "none",
      allowedDomains: [],
      allowedHttpMethods: "all",
      createdAt: new Date("2026-01-01T00:00:00.000Z"),
      updatedAt: new Date("2026-01-01T00:00:00.000Z"),
      ...overrides,
    },
  };
}
