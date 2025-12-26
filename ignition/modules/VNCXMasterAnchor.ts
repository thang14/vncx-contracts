import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";

export default buildModule("VNCXMasterAnchorModule", (m) => {
  const vncxMasterAnchor = m.contract("VNCXMasterAnchor");

  return { vncxMasterAnchor };
});

