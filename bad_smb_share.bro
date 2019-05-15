# Version 1.0 (May 2019)
#
# Authors: Zer0d0y@天御实验室 (Zer0d0y@tianyulab.com)
#
# Copyright (c) 2019, 天御[攻防]实验室.
# All rights reserved.
# Licensed under the BSD 3-Clause license. 
#
# 支持Zeek Version v2.6.x
#
# 测试：bro -C -r smb_net_user.pcap bad_smb_share.bro

@load base/frameworks/files
@load base/frameworks/notice
# @load policy/protocols/smb # For Bro Version v2.5.x

export {  redef enum Notice::Type += {  Match  };
        global isTrusted = T;  # 提供IP白名单支持
        global trustedIPs: set[addr] = {192.168.8.1,192.168.8.254} &redef;
        function hostAdminCheck(sourceip : addr) : bool
        {
                if (sourceip !in trustedIPs)
                {
                        return F;
                }
                else
                {
                        return T;
                }
        }
        event smb2_tree_connect_request(c : connection, hdr : SMB2::Header, path : string)
        {
                isTrusted = hostAdminCheck(c$id$orig_h);
                if (isTrusted == F) {
                        if ("IPC$" in path || "ADMIN$" in path || "C$" in path)
                        {
                                NOTICE([$note=Match, $msg=fmt("Potentially Malicious Use of an Administrative Share"), $sub=fmt("%s",path), $conn=c]);
                        }
                }
        }
        event smb1_tree_connect_andx_request(c : connection, hdr : SMB1::Header, path : string, service : string)
        {
                isTrusted = hostAdminCheck(c$id$orig_h);
                if (isTrusted ==F) {
                        if ("IPC$" in path || "ADMIN$" in path || "C$" in path)
                        {
                                NOTICE([$note=Match, $msg=fmt("Potentially Malicious Use of an Administrative Share"), $sub=fmt ("%s",path), $conn=c]);
                        }
                }
        }
}
