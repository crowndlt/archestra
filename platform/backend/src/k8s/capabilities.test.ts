import { describe, expect, test, vi } from "vitest";
import { getK8sCapabilitiesFromApi } from "./capabilities";

describe("Kubernetes capability inspection", () => {
  test("reports Cilium FQDN support when the CiliumNetworkPolicy CRD exists", async () => {
    const customObjectsApi = {
      getAPIResources: vi.fn().mockResolvedValue({
        resources: [{ name: "ciliumnetworkpolicies" }],
      }),
    };

    const capabilities = await getK8sCapabilitiesFromApi(
      customObjectsApi as never,
    );

    expect(customObjectsApi.getAPIResources).toHaveBeenCalledWith({
      group: "cilium.io",
      version: "v2",
    });
    expect(capabilities.networkPolicy).toMatchObject({
      kubernetesNetworkPolicy: true,
      ciliumNetworkPolicy: true,
      provider: "cilium",
      supportsFqdn: true,
      supportsHttpMethods: false,
    });
  });

  test("falls back to Kubernetes NetworkPolicy when the Cilium CRD is absent", async () => {
    const customObjectsApi = {
      getAPIResources: vi.fn().mockRejectedValue({ statusCode: 404 }),
    };

    const capabilities = await getK8sCapabilitiesFromApi(
      customObjectsApi as never,
    );

    expect(capabilities.networkPolicy).toMatchObject({
      kubernetesNetworkPolicy: true,
      ciliumNetworkPolicy: false,
      provider: "kubernetes",
      supportsFqdn: false,
      supportsHttpMethods: false,
    });
  });
});
