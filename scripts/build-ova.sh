#!/usr/bin/env bash
# =====================================================================
# Meridian · package a .vmdk into a .ova (Open Virtualization Format)
# =====================================================================
# An OVA is a tar of:
#   <name>.ovf   — XML manifest (VM specs: CPU, RAM, disk reference)
#   <name>.vmdk  — disk image, streamOptimized subformat
#   <name>.mf    — SHA256 manifest of the other two
#
# Usage:
#   ./scripts/build-ova.sh <vmdk> <out.ova> [vmname] [version]
#
# Defaults:
#   vmname  = "Meridian NIP"
#   version = pyproject.toml version
# =====================================================================

set -euo pipefail

VMDK="${1:?usage: $0 <vmdk> <out.ova> [vmname] [version]}"
OUT="${2:?usage: $0 <vmdk> <out.ova> [vmname] [version]}"
# Resolve OUT to absolute before we cd into the staging tmpdir.
case "$OUT" in /*) ;; *) OUT="$PWD/$OUT" ;; esac
VMNAME="${3:-Meridian NIP}"
VERSION="${4:-1.0.0}"

[[ -f "$VMDK" ]] || { echo "vmdk not found: $VMDK" >&2; exit 1; }

WORK=$(mktemp -d /tmp/meridian-ova.XXXXXX)
trap 'rm -rf "$WORK"' EXIT

BASENAME="meridian-nip-v${VERSION}"
cp "$VMDK" "$WORK/${BASENAME}.vmdk"

VMDK_SIZE=$(stat -c%s "$WORK/${BASENAME}.vmdk")
# Capacity = roughly the original sparse size. Use 40 GB for a v1.0 appliance.
CAP_BYTES=42949672960  # 40 * 1024^3
CAP_GB=40

cat > "$WORK/${BASENAME}.ovf" <<OVF
<?xml version="1.0" encoding="UTF-8"?>
<Envelope xmlns="http://schemas.dmtf.org/ovf/envelope/1"
          xmlns:rasd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ResourceAllocationSettingData"
          xmlns:vssd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_VirtualSystemSettingData"
          xmlns:vmw="http://www.vmware.com/schema/ovf"
          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <References>
    <File ovf:href="${BASENAME}.vmdk" ovf:id="file1" ovf:size="${VMDK_SIZE}"/>
  </References>
  <DiskSection>
    <Info>Virtual disks</Info>
    <Disk ovf:capacity="${CAP_BYTES}" ovf:capacityAllocationUnits="byte"
          ovf:diskId="vmdisk1" ovf:fileRef="file1"
          ovf:format="http://www.vmware.com/interfaces/specifications/vmdk.html#streamOptimized"/>
  </DiskSection>
  <NetworkSection>
    <Info>The list of logical networks</Info>
    <Network ovf:name="bridged">
      <Description>Bridge to the host LAN so the appliance gets a DHCP lease</Description>
    </Network>
  </NetworkSection>
  <VirtualSystem ovf:id="${VMNAME}">
    <Info>Meridian NIP — self-hosted DDI + network-ops portal (Apache 2.0)</Info>
    <Name>${VMNAME}</Name>
    <OperatingSystemSection ovf:id="96" vmw:osType="debian13_64Guest">
      <Info>Guest OS</Info>
      <Description>Debian GNU/Linux 13 (64-bit)</Description>
    </OperatingSystemSection>
    <VirtualHardwareSection>
      <Info>Virtual hardware</Info>
      <System>
        <vssd:ElementName>Virtual Hardware Family</vssd:ElementName>
        <vssd:InstanceID>0</vssd:InstanceID>
        <vssd:VirtualSystemIdentifier>${VMNAME}</vssd:VirtualSystemIdentifier>
        <vssd:VirtualSystemType>vmx-15</vssd:VirtualSystemType>
      </System>
      <Item>
        <rasd:AllocationUnits>hertz * 10^6</rasd:AllocationUnits>
        <rasd:Description>Virtual CPU</rasd:Description>
        <rasd:ElementName>2 vCPUs</rasd:ElementName>
        <rasd:InstanceID>1</rasd:InstanceID>
        <rasd:ResourceType>3</rasd:ResourceType>
        <rasd:VirtualQuantity>2</rasd:VirtualQuantity>
      </Item>
      <Item>
        <rasd:AllocationUnits>byte * 2^20</rasd:AllocationUnits>
        <rasd:Description>Memory</rasd:Description>
        <rasd:ElementName>4096 MB</rasd:ElementName>
        <rasd:InstanceID>2</rasd:InstanceID>
        <rasd:ResourceType>4</rasd:ResourceType>
        <rasd:VirtualQuantity>4096</rasd:VirtualQuantity>
      </Item>
      <Item>
        <rasd:Address>0</rasd:Address>
        <rasd:Description>SCSI controller</rasd:Description>
        <rasd:ElementName>scsiController0</rasd:ElementName>
        <rasd:InstanceID>3</rasd:InstanceID>
        <rasd:ResourceSubType>lsilogic</rasd:ResourceSubType>
        <rasd:ResourceType>6</rasd:ResourceType>
      </Item>
      <Item>
        <rasd:AddressOnParent>0</rasd:AddressOnParent>
        <rasd:ElementName>disk0</rasd:ElementName>
        <rasd:HostResource>ovf:/disk/vmdisk1</rasd:HostResource>
        <rasd:InstanceID>4</rasd:InstanceID>
        <rasd:Parent>3</rasd:Parent>
        <rasd:ResourceType>17</rasd:ResourceType>
      </Item>
      <Item>
        <rasd:AddressOnParent>2</rasd:AddressOnParent>
        <rasd:AutomaticAllocation>true</rasd:AutomaticAllocation>
        <rasd:Connection>bridged</rasd:Connection>
        <rasd:Description>Bridged network adapter</rasd:Description>
        <rasd:ElementName>ethernet0</rasd:ElementName>
        <rasd:InstanceID>5</rasd:InstanceID>
        <rasd:ResourceSubType>VmxNet3</rasd:ResourceSubType>
        <rasd:ResourceType>10</rasd:ResourceType>
      </Item>
    </VirtualHardwareSection>
  </VirtualSystem>
</Envelope>
OVF

# Manifest with SHA256 of OVF + VMDK (.mf is required by the OVF spec)
cd "$WORK"
{
  echo "SHA256(${BASENAME}.ovf)= $(sha256sum ${BASENAME}.ovf | awk '{print $1}')"
  echo "SHA256(${BASENAME}.vmdk)= $(sha256sum ${BASENAME}.vmdk | awk '{print $1}')"
} > "${BASENAME}.mf"

# OVA = ustar of ovf + vmdk + mf, in that specific order
tar -cf "$OUT" "${BASENAME}.ovf" "${BASENAME}.vmdk" "${BASENAME}.mf"

echo "wrote $OUT ($(stat -c%s "$OUT") bytes)"
