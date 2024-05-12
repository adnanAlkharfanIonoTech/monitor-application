package org.iono;

import org.snmp4j.*;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.fluent.SnmpBuilder;
import org.snmp4j.fluent.SnmpCompletableFuture;
import org.snmp4j.fluent.TargetBuilder;
import org.snmp4j.mp.MPv3;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.security.*;
import org.snmp4j.smi.*;
import org.snmp4j.transport.DefaultUdpTransportMapping;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.lang.management.MemoryUsage;
import java.net.*;
import java.io.IOException;
import java.net.SocketException;
import java.nio.file.FileStore;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.stream.Stream;

public class Main  {
    public static void sendPingRequest(String ipAddress)
            throws UnknownHostException, IOException
    {
        InetAddress geek = InetAddress.getByName(ipAddress);
        System.out.println("Sending Ping Request to " + ipAddress);
        if (geek.isReachable(5000))
            System.out.println("Host is reachable");
        else
            System.out.println("Sorry ! We can't reach to this host");
    }
    public static void testWithPort(String ipAddress, int port) {
        try {
            Socket socket = new Socket(ipAddress, port);
            System.out.println("HTTP Connection successful to " + ipAddress + ":" + port);
            socket.close();
        } catch (IOException e) {
            System.out.println("HTTP Connection failed to " + ipAddress + ":" + port);
        }
    }

    // Test HTTPS connectivity
    public static void testHTTPS(String ipAddress, int port) {
        try {
            SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            SSLSocket socket = (SSLSocket) factory.createSocket(ipAddress, port);
            System.out.println("HTTPS Connection successful to " + ipAddress + ":" + port);
            socket.close();
        } catch (IOException e) {
            System.out.println("HTTPS Connection failed to " + ipAddress + ":" + port);
        }
    }
//    private String community;
//    private int port;
//    private int retries;
//    private int timeout;
//
//    private String ipAddress; // IP address or hostname to listen on
//
//    public Main(String community, int port, int retries, int timeout, String ipAddress) throws Exception {
//        super(new DefaultUdpTransportMapping(new UdpAddress(ipAddress + "/" + port)));
//        this.community = community;
//        this.port = port;
//        this.retries = retries;
//        this.timeout = timeout;
//        this.ipAddress = ipAddress;
//
//        // Add the command responder to listen for trap events
//        this.addCommandResponder(this);
//    }
//
//    public void start() throws Exception {
//        this.listen();
//    }
//
//    @Override
//    public void processPdu(CommandResponderEvent event) {
//        // Handle received trap here
//        System.out.println("Received trap: " + event.getPDU());
//    }


    public static void main(String[] args) throws Exception {
//        String community = "public";
//        int port = 162;
//        int retries = 5;
//        int timeout = 5000;
//
//        String ipAddress = "192.168.100.38"; // Example IP address
//
//        Main snmpManager = new Main(community, port, retries, timeout, ipAddress);
//        snmpManager.start();
//        File file = new File("/");
//        long totalSpace = file.getTotalSpace();
//        System.out.println("Hard Disk ID: " + totalSpace);

//        try {
//            // Execute the command
//            Process process = Runtime.getRuntime().exec("cmd /c wmic baseboard get serialnumber");
//
//            // Read the output from the command
//            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
//
//            String line;
//            String serialNumber = null;
//
//            // Read each line of output until serial number is found
//            while ((line = reader.readLine()) != null) {
//                if (line.toLowerCase().contains("serialnumber")) {
//                    // Extract serial number (assuming it's after the colon)
//                    serialNumber = line.split(":")[1].trim();
//                    break;
//                }
//            }
//
//            reader.close();
//
//            // Check if serial number was found
//            if (serialNumber != null) {
//                System.out.println("Motherboard Serial Number: " + serialNumber);
//            } else {
//                System.out.println("Motherboard Serial Number not found.");
//            }
//
//        } catch (IOException e) {
//            System.err.println("Error: " + e.getMessage());
//
//        }
//try{
//        Iterable<FileStore> fileStores = FileSystems.getDefault().getFileStores();
//
//        // Loop through each file store
//        for (FileStore store : fileStores) {
//            // Print file store name (unique identifier on most systems)
//            System.out.println("Disk Name: " + store.name());
//        }}catch (Exception e){
//    System.out.println(e.getMessage());
//}
//        try {
//            Process process = Runtime.getRuntime().exec(new String[]{"wmic", "cpu", "get", "ProcessorId"});
//            process.getOutputStream().close();
//            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
//
//            String line;
//            while ((line = reader.readLine()) != null) {
//                if (!line.trim().isEmpty()) {
//                    // Assuming ProcessorId is in the first column
//                    String cpuId = line.trim();
//                    System.out.println("CPU ID: " + cpuId);
//                    break; // Assuming only one CPU ID, so break after the first non-empty line
//                }
//            }
//            reader.close();
//        } catch (Exception e) {
//            e.printStackTrace();
//        }

//        MemoryMXBean memoryMXBean = ManagementFactory.getMemoryMXBean();
//        MemoryUsage heapMemoryUsage = memoryMXBean.getHeapMemoryUsage();
//
//        System.out.println("Initial Heap Memory: " + heapMemoryUsage.getInit() / (1024 * 1024) + " MB");
//        System.out.println("Max Heap Memory: " + heapMemoryUsage.getMax() / (1024 * 1024) + " MB");
//        System.out.println("Used Heap Memory: " + heapMemoryUsage.getUsed() / (1024 * 1024) + " MB");

//        String ipAddress = "127.0.0.1";
//        sendPingRequest(ipAddress);
//
//        ipAddress = "192.168.100.18";
//        sendPingRequest(ipAddress);
//
//        ipAddress = "192.168.100.225";
//        sendPingRequest(ipAddress);
//
//        testWithPort("192.168.100.18",80);
//        testHTTPS("google.com",443);



        
//snmp v3...................................................
        try {


            SnmpBuilder snmpBuilder = new SnmpBuilder();
            Snmp snmp = snmpBuilder.udp().securityProtocols(SecurityProtocols.SecurityProtocolSet.maxCompatibility).v3().usm().threads(2).build();
snmp.listen();
            Address targetAddress = GenericAddress.parse("udp:192.168.100.38/161");
            byte[] targetEngineID = snmp.discoverAuthoritativeEngineID(targetAddress, 10000);

            if (targetEngineID != null) {
//            System.out.println("Trying with " + authPro.toString());
                TargetBuilder<?> targetBuilder = snmpBuilder.target(targetAddress);

                Target<?> target = targetBuilder
                        .user("adnanadnan", targetEngineID)
                        .auth(TargetBuilder.AuthProtocol.md5).authPassphrase("adnanadnan")
                        .priv(TargetBuilder.PrivProtocol.des).privPassphrase("adnanadnan")
                        .done()
                        .timeout(15000).retries(5)
                        .build();
                target.setVersion(SnmpConstants.version3);
                PDU pdu = targetBuilder.pdu().type(PDU.GET).oids(".1.3.6.1.2.1.1.8.0").contextName("").build();
                SnmpCompletableFuture snmpRequestFuture = SnmpCompletableFuture.send(snmp, target, pdu);


                try {
                    List<VariableBinding> vbs = snmpRequestFuture.get().getAll();
                    System.out.println("Received: " + snmpRequestFuture.getResponseEvent().getResponse());
                    System.out.println("Payload:  " + vbs);
                } catch (ExecutionException | InterruptedException ex) {
                    System.err.println("Request failed: " + ex.getCause().getMessage());
                }
            } else {
                System.err.println("Timeout on engine ID discovery for " + targetAddress + ", GET not sent.");
            }
            snmp.close();

        }catch (Exception e){
            System.err.println(e.getMessage());
        }


//        String targetIP = "192.168.100.38";
//        String community = "public";
//        int port = 161;
//        int retries = 5;
//        int timeout = 5000;




//        TransportMapping<? extends Address> transport;
//        Snmp snmp = null;
//        OctetString authoritativeEngineID=new OctetString(MPv3.createLocalEngineID());
//        try
//        {
//            transport = new DefaultUdpTransportMapping();
//            snmp = new Snmp(transport);
//            USM usm = new USM(SecurityProtocols.getInstance(),authoritativeEngineID, 0);
//            SecurityModels.getInstance().addSecurityModel(usm);
//         // transport.listen();
//            snmp.listen();
//        }
//        catch (IOException e)
//        {
//            e.printStackTrace();
//        }
//        snmp.getUSM().addUser(new OctetString("adnanadnan"),authoritativeEngineID,
//                new UsmUser(new OctetString("adnanadnan"),
//                        AuthMD5.ID,
//                        new OctetString("adnanadnan"),
//                        PrivDES.ID,
//                        new OctetString("adnanadnan")));
//        PDU pdu = new ScopedPDU();
//        pdu.add(new VariableBinding(new OID(".1.3.6.1.4.1.258.5100.100.1.2.1.0")));
//        pdu.setType(PDU.GET);
//        UserTarget target = new UserTarget();
//        Address targetAddress = GenericAddress.parse(String.format("udp:%s/%s", targetIP, port));
//        target.setAddress(targetAddress);
//        target.setRetries(retries);
//        target.setTimeout(timeout);
//        target.setVersion(SnmpConstants.version3);
//
//
//     target.setSecurityModel(SecurityModel.SECURITY_MODEL_USM);
//        ResponseEvent response;
//        try
//        {
//            response = snmp.send(pdu, target);
//            // extract the response PDU (could be null if timed out)
//            PDU responsePDU = response.getResponse();
//            // extract the address used by the agent to send the response:
//            if(responsePDU == null)
//            {
//                System.out.println("ERROR: table OID [.1.3.6.1.4.1.258.5100.100.1.2.1.0] due: "+response.getError() );
//            }
//            else
//            {
//                Address peerAddress = response.getPeerAddress();
//                System.out.println("pdu: "+responsePDU.toString());
//                System.out.println("Address: "+peerAddress.toString());
//                System.out.println(responsePDU.get(0).getVariable().toString());
//            }
//        }
//        catch (IOException e)
//        {
//            e.printStackTrace();
//        }
//        finally
//        {
//            try
//            {
//                snmp.close();
//            } catch (IOException e)
//            {
//                System.out.println(e.getMessage());
//                e.printStackTrace();
//            }
//        }


        // OID to start traversing the subtree from
//        String rootOidString = ".1.3"; // Replace with your desired OID

//        TransportMapping<? extends Address> transport = new DefaultUdpTransportMapping();
//        Snmp snmp = new Snmp(transport);
//
//        OctetString localEngineId = new OctetString(MPv3.createLocalEngineID());
//        USM usm = new USM(SecurityProtocols.getInstance(), localEngineId, 0);
//        SecurityModels.getInstance().addSecurityModel(usm);
//
//        OctetString securityName = new OctetString("adnanadnan");
//        OID authProtocol = AuthMD5.ID;
//        OID privProtocol = PrivDES.ID;
//        OctetString authPassphrase = new OctetString("adnanadnan");
//        OctetString privPassphrase = new OctetString("adnanadnan");
//
//        snmp.getUSM().addUser( new UsmUser(securityName, authProtocol, authPassphrase, privProtocol, privPassphrase));
//      SecurityModels.getInstance().addSecurityModel(new TSM(localEngineId, false));
//
//        UserTarget target = new UserTarget();
//
//
//
//        target.setAddress(GenericAddress.parse(String.format("udp:%s/%s", targetIP, port)));
//
//        target.setRetries(retries);
//        target.setTimeout(timeout);
//
//        PDU pdu = new ScopedPDU();
//        pdu.setType(PDU.GET);
//        pdu.add(new VariableBinding(new OID(".1.3.6.1.4.1.258.5100.100.1.2.1.0")));
//        snmp.listen();
//        ResponseEvent response = snmp.get(pdu, target);
//if(response!=null && response.getResponse()!=null){
//    System.out.println("response not null.");
//   for (int i=0;i<response.getResponse().getAll().size();i++){
//       System.out.println(response.getResponse().get(i).getOid());
//       System.out.println(response.getResponse().get(i).toValueString());
//   }
//}else{
//    System.out.println(response.getError().getMessage());
//}


    }
}