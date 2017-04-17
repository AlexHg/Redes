package captura;

/**
 *
 * @author Antonio_RF
 */
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.io.*;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapAddr;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.PcapBpfProgram;


public class Captura {

	/**
	 * Main startup method
	 *
	 * @param args
	 *          ignored
	 */
   private static String asString(final byte[] mac) {
    final StringBuilder buf = new StringBuilder();
    for (byte b : mac) {
      if (buf.length() != 0) {
        buf.append(':');
      }
      if (b >= 0 && b < 16) {
        buf.append('0');
      }
      buf.append(Integer.toHexString((b < 0) ? b + 256 : b).toUpperCase());
    }

    return buf.toString();
  }

	public static void main(String[] args) {
            Pcap pcap=null;
               try{
                BufferedReader br = new BufferedReader(new InputStreamReader(System.in));   
		List<PcapIf> alldevs = new ArrayList<PcapIf>(); // Will be filled with NICs
		StringBuilder errbuf = new StringBuilder(); // For any error msgs
                System.out.println("[0]-->Realizar captura de paquetes al vuelo");
                System.out.println("[1]-->Cargar traza de captura desde archivo");
                System.out.print("\nElige una de las opciones:");
                int opcion = Integer.parseInt(br.readLine());
                if (opcion==1){
                    
                    /////////////////////////lee archivo//////////////////////////
                //String fname = "archivo.pcap";
                String fname = "paquetes3.pcap";
                pcap = Pcap.openOffline(fname, errbuf);
                if (pcap == null) {
                  System.err.printf("Error while opening device for capture: "+ errbuf.toString());
                  return;
                 }//if
                } else if(opcion==0){
		/***************************************************************************
		 * First get a list of devices on this system
		 **************************************************************************/
		int r = Pcap.findAllDevs(alldevs, errbuf);
		if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
			System.err.printf("Can't read list of devices, error is %s", errbuf
			    .toString());
			return;
		}

		System.out.println("Network devices found:");

		int i = 0;
		for (PcapIf device : alldevs) {
			String description =
			    (device.getDescription() != null) ? device.getDescription()
			        : "No description available";
                        final byte[] mac = device.getHardwareAddress();
			String dir_mac = (mac==null)?"No tiene direccion MAC":asString(mac);
                        System.out.printf("#%d: %s [%s] MAC:[%s]\n", i++, device.getName(), description, dir_mac);
                        List<PcapAddr> direcciones = device.getAddresses();
                        for(PcapAddr direccion:direcciones){
                            System.out.println(direccion.getAddr().toString());
                        }//foreach

		}//for
                
                System.out.print("\nEscribe el número de interfaz a utilizar:");
                int interfaz = Integer.parseInt(br.readLine());
		PcapIf device = alldevs.get(interfaz); // We know we have atleast 1 device
		System.out
		    .printf("\nChoosing '%s' on your behalf:\n",
		        (device.getDescription() != null) ? device.getDescription()
		            : device.getName());
                
		/***************************************************************************
		 * Second we open up the selected device
		 **************************************************************************/
                /*"snaplen" is short for 'snapshot length', as it refers to the amount of actual data captured from each packet passing through the specified network interface.
                64*1024 = 65536 bytes; campo len en Ethernet(16 bits) tam máx de trama */

		int snaplen = 64 * 1024;           // Capture all packets, no trucation
		int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
		int timeout = 10 * 1000;           // 10 seconds in millis

                
                pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);

		if (pcap == null) {
			System.err.printf("Error while opening device for capture: "
			    + errbuf.toString());
			return;
		}//if
                  
                       /********F I L T R O********/
            PcapBpfProgram filter = new PcapBpfProgram();
            String expression =""; // "port 80";
            int optimize = 0; // 1 means true, 0 means false
            int netmask = 0;
            int r2 = pcap.compile(filter, expression, optimize, netmask);
            if (r2 != Pcap.OK) {
                System.out.println("Filter error: " + pcap.getErr());
            }//if
            pcap.setFilter(filter);
                /****************/
            }//else if

		PcapPacketHandler<String> jpacketHandler;
                jpacketHandler = new PcapPacketHandler<String>() {
                    private Object array;
                    
                    public void nextPacket(PcapPacket packet, String user) {
                        
                        System.out.printf("\n\nPaquete recibido el %s \ncaplen=%-4d \nlongitud=%-4d %s\n\n",
                                new Date(packet.getCaptureHeader().timestampInMillis()),
                                packet.getCaptureHeader().caplen(),  // Length actually captured
                                packet.getCaptureHeader().wirelen(), // Original length
                                user                                 // User supplied object
                        );
                        
                        
                        /******Desencapsulado********/
                        for(int i=0;i<packet.size();i++){
                            System.out.printf("%02X ",packet.getUByte(i));
                            
                            if(i%16==15)
                                System.out.println("");
                        }//if
                        
                        int longitud = (packet.getUByte(12)*256)+packet.getUByte(13);
                        System.out.printf("\nLongitud: %d (%04X)",longitud,longitud );
                        if(longitud<1500){
                            System.out.println("\nTrama IEEE802.3");
                            System.out.printf("MAC Destino: %02X:%02X:%02X:%02X:%02X:%02X",packet.getUByte(0),packet.getUByte(1),packet.getUByte(2),packet.getUByte(3),packet.getUByte(4),packet.getUByte(5));
                            System.out.printf("\nMAC Origen: %02X:%02X:%02X:%02X:%02X:%02X",packet.getUByte(6),packet.getUByte(7),packet.getUByte(8),packet.getUByte(9),packet.getUByte(10),packet.getUByte(11));
                            //System.out.printf("\nDSAP: %02X",packet.getUByte(14));
                            int dsap = packet.getUByte(14)& 0x00000001;
                            String c_r1 = (dsap==1)?"\nEs una G debido al bit menos significativo del DSAP en (1)  ":(dsap==0)?"\nEs un I por el bit menos significativo en (0) del DSAP":"\n";
                            System.out.printf("\nDSAP: %02X   %s",packet.getUByte(14), c_r1);
                            //System.out.println(packet.getUByte(15)& 0x00000001);
                            int ssap = packet.getUByte(15)& 0x00000001;
                            String c_r = (ssap==1)?"\nEs una respuesta debido al bit menos significativo del SSAP en (1)  ":(ssap==0)?"\nEs un comando por el bit menos significativo en (0) del SSAP":"\n Otro";
                            System.out.printf("\nSSAP: %02X   %s",packet.getUByte(15), c_r);
                            
                            if (longitud==3)
                            {
                                System.out.printf("\nCampo de control en hexadecimal: %02X",packet.getUByte(16));
                                String campo_control_bin=Integer.toBinaryString(packet.getUByte(16));                                
                                while(campo_control_bin.length()!=8)
                                {
                                    campo_control_bin="0"+campo_control_bin;
                                }                                
                                //System.out.printf("\nCampo de control en binario: "+campo_control_bin);
                                String cad="";
                                int t=campo_control_bin.length();
                                for(int i=t;i>0;i--)
                                {
                                   cad=cad+campo_control_bin.substring((i-1), i);
                                }
                                System.out.printf("\nCampo de control en binario de forma invertida: "+cad);    
                                if(cad.startsWith("0"))
                                {
                                    System.out.printf("\nTipo de Trama: De Información (Empieza con '0')");  
                                    if(cad.length()<5)
                                    {
                                        System.out.printf("\nN(s): "+cad.substring(1, 4));  
                                    }
                                    if(cad.length()>5)
                                    {
                                        System.out.printf("\nN(s): "+cad.substring(1, 8));
                                        System.out.printf("\nN(r): "+cad.substring(9, cad.length()));
                                    }
                                }
                                if(cad.startsWith("10"))
                                {
                                    System.out.printf("\nN(r): "+cad.substring(9, cad.length()));
                                    System.out.printf("\nTipo de Trama: De Supervisión (Empieza con '10')");
                                    if(cad.length()>5)
                                    {
                                        System.out.printf("\nN(r): "+cad.substring(9, cad.length()));
                                    }
                                    String codigo=cad.substring(2, 4);
                                    System.out.printf("\nCodigo: "+codigo);
                                    if(codigo.equals("00"))
                                    {
                                    System.out.printf("\nOrden: RR ");
                                    }
                                    if(codigo.equals("01"))
                                    {
                                    System.out.printf("\nOrden: REJ ");
                                    }
                                    if(codigo.equals("10"))
                                    {
                                    System.out.printf("\nOrden: RNR ");
                                    }
                                    if(codigo.equals("11"))
                                    {
                                    System.out.printf("\nOrden: SREJ ");
                                    }
                                }
                                if(cad.startsWith("11"))
                                {
                                    System.out.printf("\nTipo de Trama: No Numerada (Empieza con '11')");  
                                    String codigo=cad.substring(2, 4)+cad.substring(5, 8);
                                    System.out.printf("\nCodigo: "+codigo);                                    
                                    if(codigo.equals("00001"))
                                    {
                                    System.out.printf("\nOrden: SNRM ");
                                    }
                                    if(codigo.equals("10011"))
                                    {
                                    System.out.printf("\nOrden: SNRME ");
                                    }
                                    if(codigo.equals("11000"))
                                    {
                                    System.out.printf("\nOrden: SARM ");
                                    }
                                    if(codigo.equals("11100"))
                                    {
                                    System.out.printf("\nOrden: SABM ");
                                    }
                                    if(codigo.equals("11110"))
                                    {
                                    System.out.printf("\nOrden: SABME ");
                                    }
                                    if(codigo.equals("00000"))
                                    {
                                    System.out.printf("\nOrden: UI ");
                                    }
                                    if(codigo.equals("00110"))
                                    {
                                    System.out.printf("\nOrden: - ");
                                    }
                                    if(codigo.equals("00010"))
                                    {
                                    System.out.printf("\nOrden: DISC ");
                                    }
                                    if(codigo.equals("11001"))
                                    {
                                    System.out.printf("\nOrden: RSET ");
                                    }
                                    if(codigo.equals("11101"))
                                    {
                                    System.out.printf("\nOrden: XID ");
                                    }                                    
                                }
                            }
                            
                            
                            if(longitud>3)
                            {
                                System.out.printf("\nCampo de control en hexadecimal: %02X %02X",packet.getUByte(16),packet.getUByte(17));
                                String campo_control_bin_1=Integer.toBinaryString(packet.getUByte(16));
                                while(campo_control_bin_1.length()!=8)
                                {
                                    campo_control_bin_1="0"+campo_control_bin_1;
                                } 
                                String campo_control_bin_2=Integer.toBinaryString(packet.getUByte(17));
                                
                                while(campo_control_bin_2.length()!=8)
                                {
                                    campo_control_bin_2="0"+campo_control_bin_2;
                                } 
                                String campo_control_bin=campo_control_bin_1+campo_control_bin_2;
                                //System.out.printf("\nCampo de control en binario 1: "+campo_control_bin_1);
                                //System.out.printf("\nCampo de control en binario 2: "+campo_control_bin_2);
                                //System.out.printf("\nCampo de control en binario: "+campo_control_bin);                               
                                String cad="";
                                int t=campo_control_bin.length();
                                for(int i=t;i>0;i--)
                                {
                                   cad=cad+campo_control_bin.substring((i-1), i);
                                }
                                System.out.printf("\nCampo de control en binario de forma invertida: "+cad);    
                                if(cad.startsWith("0"))
                                {
                                    System.out.printf("\nTipo de Trama: De Información (Empieza con '0')");  
                                    if(cad.length()<5)
                                    {
                                        System.out.printf("\nN(s): "+cad.substring(1, 4));  
                                    }
                                    if(cad.length()>5)
                                    {
                                        System.out.printf("\nN(s): "+cad.substring(1, 8));
                                        System.out.printf("\nN(r): "+cad.substring(9, cad.length()));
                                    }
                                }
                                if(cad.startsWith("10"))
                                {
                                    System.out.printf("\nTipo de Trama: De Supervisión (Empieza con '10')"); 
                                    if(cad.length()<5)
                                    {
                                        System.out.printf("\nN(r): "+cad.substring(8, cad.length()));
                                    }
                                    String codigo=cad.substring(2, 4);
                                    System.out.printf("\nCodigo: "+codigo);
                                    if(codigo.equals("00"))
                                    {
                                    System.out.printf("\nOrden: RR ");
                                    }
                                    if(codigo.equals("01"))
                                    {
                                    System.out.printf("\nOrden: REJ ");
                                    }
                                    if(codigo.equals("10"))
                                    {
                                    System.out.printf("\nOrden: RNR ");
                                    }
                                    if(codigo.equals("11"))
                                    {
                                    System.out.printf("\nOrden: SREJ ");
                                    }
                                }
                                if(cad.startsWith("11"))
                                {
                                    System.out.printf("\nTipo de Trama: No Numerada (Empieza con '11')");
                                    String codigo=cad.substring(2, 4)+cad.substring(5, 8);
                                    System.out.printf("\nCodigo: "+codigo);
                                    if(codigo.equals("00001"))
                                    {
                                    System.out.printf("\nOrden: SNRM ");
                                    }
                                    if(codigo.equals("10011"))
                                    {
                                    System.out.printf("\nOrden: SNRME ");
                                    }
                                    if(codigo.equals("11000"))
                                    {
                                    System.out.printf("\nOrden: SARM ");
                                    }
                                    if(codigo.equals("11100"))
                                    {
                                    System.out.printf("\nOrden: SABM ");
                                    }
                                    if(codigo.equals("11110"))
                                    {
                                    System.out.printf("\nOrden: SABME ");
                                    }
                                    if(codigo.equals("00000"))
                                    {
                                    System.out.printf("\nOrden: UI ");
                                    }
                                    if(codigo.equals("00110"))
                                    {
                                    System.out.printf("\nOrden: - ");
                                    }
                                    if(codigo.equals("00010"))
                                    {
                                    System.out.printf("\nOrden: DISC ");
                                    }
                                    if(codigo.equals("11001"))
                                    {
                                    System.out.printf("\nOrden: RSET ");
                                    }
                                    if(codigo.equals("11101"))
                                    {
                                    System.out.printf("\nOrden: XID ");
                                    }     
                                    
                                }
                            }
                            
                            
                        } 
                        else if(longitud>=1500){
                            System.out.println("-->Trama ETHERNET");
                        }else
                            
                            
                            System.out.println("\n\nEncabezado: "+ packet.toHexdump());
                        
                        
                    }
                };


		/***************************************************************************
		 * Fourth we enter the loop and tell it to capture 10 packets. The loop
		 * method does a mapping of pcap.datalink() DLT value to JProtocol ID, which
		 * is needed by JScanner. The scanner scans the packet buffer and decodes
		 * the headers. The mapping is done automatically, although a variation on
		 * the loop method exists that allows the programmer to sepecify exactly
		 * which protocol ID to use as the data link type for this pcap interface.
		 **************************************************************************/
		pcap.loop(-1, jpacketHandler, " ");

		/***************************************************************************
		 * Last thing to do is close the pcap handle
		 **************************************************************************/
		pcap.close();
                }catch(IOException e){e.printStackTrace();}
	}
}
