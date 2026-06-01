import { describe, expect, test } from "@/test";
import type { EffectiveNetworkPolicy } from "@/types";
import {
  buildManagedCiliumNetworkPolicy,
  buildManagedGkeFqdnNetworkPolicy,
  buildManagedNetworkPolicy,
  constructManagedNetworkPolicyName,
  shouldManageK8sNetworkPolicy,
  shouldUseCiliumNetworkPolicy,
  shouldUseGkeFqdnNetworkPolicy,
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
            "requires-fqdn-policy-provider",
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

  test("builds a restricted Kubernetes policy with DNS and CIDR egress", () => {
    const manifest = buildManagedNetworkPolicy({
      name: "mcp-egress-test",
      podSelectorLabels: {
        app: "mcp-server",
        "mcp-server-id": "server-id",
      },
      effectivePolicy: makeEffectivePolicy({
        egressMode: "restricted",
        allowedDomains: ["registry.npmjs.org"],
        allowedCidrs: ["203.0.113.0/24"],
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
      {
        to: [{ ipBlock: { cidr: "203.0.113.0/24" } }],
      },
    ]);
    expect(manifest.metadata?.annotations).toMatchObject({
      "archestra.io/network-policy-allowed-domains": "registry.npmjs.org",
      "archestra.io/network-policy-allowed-cidrs": "203.0.113.0/24",
      "archestra.io/network-policy-allowed-http-methods": "read_only",
      "archestra.io/network-policy-domain-enforcement":
        "requires-fqdn-policy-provider",
      "archestra.io/network-policy-http-method-enforcement": "not-supported",
    });
  });

  test("builds a Cilium policy with FQDN and CIDR egress", () => {
    const manifest = buildManagedCiliumNetworkPolicy({
      name: "mcp-egress-test",
      podSelectorLabels: {
        app: "mcp-server",
        "mcp-server-id": "server-id",
      },
      effectivePolicy: makeEffectivePolicy({
        egressMode: "restricted",
        domainPreset: "package_managers",
        allowedDomains: ["api.example.com", "*.example.org"],
        allowedCidrs: ["203.0.113.0/24"],
      }),
    });

    expect(manifest).toMatchObject({
      apiVersion: "cilium.io/v2",
      kind: "CiliumNetworkPolicy",
      spec: {
        endpointSelector: {
          matchLabels: {
            app: "mcp-server",
            "mcp-server-id": "server-id",
          },
        },
        egress: [
          {
            toEndpoints: [
              {
                matchLabels: {
                  "k8s:io.kubernetes.pod.namespace": "kube-system",
                  "k8s:k8s-app": "kube-dns",
                },
              },
            ],
            toPorts: [
              {
                ports: [{ port: "53", protocol: "ANY" }],
                rules: {
                  dns: [{ matchPattern: "*" }],
                },
              },
            ],
          },
          {
            toCIDRSet: [{ cidr: "203.0.113.0/24" }],
          },
          {
            toFQDNs: expect.arrayContaining([
              { matchName: "registry.npmjs.org" },
              { matchName: "api.example.com" },
              { matchPattern: "*.example.org" },
            ]),
          },
        ],
      },
    });
  });

  test("builds a GKE FQDN policy with exact and wildcard domains", () => {
    const manifest = buildManagedGkeFqdnNetworkPolicy({
      name: "mcp-egress-test",
      podSelectorLabels: {
        app: "mcp-server",
        "mcp-server-id": "server-id",
      },
      effectivePolicy: makeEffectivePolicy({
        egressMode: "restricted",
        allowedDomains: ["api.example.com", "*.example.org"],
      }),
    });

    expect(manifest).toMatchObject({
      apiVersion: "networking.gke.io/v1alpha1",
      kind: "FQDNNetworkPolicy",
      spec: {
        podSelector: {
          matchLabels: {
            app: "mcp-server",
            "mcp-server-id": "server-id",
          },
        },
        egress: [
          {
            matches: [
              { name: "api.example.com" },
              { pattern: "*.example.org" },
            ],
          },
        ],
      },
    });
  });

  test("uses Cilium only when Cilium is available and domain rules exist", () => {
    const policy = makeEffectivePolicy({
      egressMode: "restricted",
      allowedDomains: ["api.example.com"],
    });

    expect(
      shouldUseCiliumNetworkPolicy({
        effectivePolicy: policy,
        capabilities: {
          kubernetesNetworkPolicy: true,
          ciliumNetworkPolicy: true,
          gkeFqdnNetworkPolicy: false,
          provider: "cilium",
          supportsFqdn: true,
          supportsHttpMethods: false,
          message: null,
        },
      }),
    ).toBe(true);
    expect(
      shouldUseCiliumNetworkPolicy({
        effectivePolicy: policy,
        capabilities: {
          kubernetesNetworkPolicy: true,
          ciliumNetworkPolicy: false,
          gkeFqdnNetworkPolicy: false,
          provider: "kubernetes",
          supportsFqdn: false,
          supportsHttpMethods: false,
          message: null,
        },
      }),
    ).toBe(false);
  });

  test("uses GKE FQDN policy when GKE is available and Cilium is not", () => {
    const policy = makeEffectivePolicy({
      egressMode: "restricted",
      allowedDomains: ["api.example.com"],
    });

    expect(
      shouldUseGkeFqdnNetworkPolicy({
        effectivePolicy: policy,
        capabilities: {
          kubernetesNetworkPolicy: true,
          ciliumNetworkPolicy: false,
          gkeFqdnNetworkPolicy: true,
          provider: "gke-fqdn",
          supportsFqdn: true,
          supportsHttpMethods: false,
          message: null,
        },
      }),
    ).toBe(true);
    expect(
      shouldUseGkeFqdnNetworkPolicy({
        effectivePolicy: policy,
        capabilities: {
          kubernetesNetworkPolicy: true,
          ciliumNetworkPolicy: true,
          gkeFqdnNetworkPolicy: true,
          provider: "cilium",
          supportsFqdn: true,
          supportsHttpMethods: false,
          message: null,
        },
      }),
    ).toBe(false);
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
      allowedCidrs: [],
      allowedHttpMethods: "all",
      createdAt: new Date("2026-01-01T00:00:00.000Z"),
      updatedAt: new Date("2026-01-01T00:00:00.000Z"),
      ...overrides,
    },
  };
}
