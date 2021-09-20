import time
import rrdtool
import os
from pysnmp.hlapi import *
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

def agregarElemento (lista,comunidad,direccion,version,puerto):
    if(lista[0]==0):
        lista.pop()
    lista.extend([direccion,comunidad,version,puerto])

def imprimirLista (lista):
    print(lista[:])

def eliminarAgente (lista,direccion):
    dex=lista.index(direccion)
    dex2=dex+3
    i=int(dex)
    i=(i/4)+1
    archivo="agente"+str(int(i))
    os.remove(archivo+".rrd")
    os.remove(archivo + ".xml")
    os.remove(archivo + "ICMP.png")
    os.remove(archivo + "UDP.png")
    os.remove(archivo + "TCP.png")
    os.remove(archivo + "OutRequest.png")
    os.remove(archivo + "NUncast.png")
    os.remove("Reporte del "+archivo+".pdf")
    while (dex<=dex2):
        lista.pop(dex2)
        dex2-=1

def consultaSNMP(comunidad,host,oid,puerto):
    errorIndication, errorStatus, errorIndex, varBinds = next(
        getCmd(SnmpEngine(),
               CommunityData(comunidad),
               UdpTransportTarget((host, puerto)),
               ContextData(),
               ObjectType(ObjectIdentity(oid))))

    if errorIndication:
        resultado=errorIndication
    elif errorStatus:
        print('%s at %s' % (errorStatus.prettyPrint(),errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
    else:
        for varBind in varBinds:
            varB=(' = '.join([x.prettyPrint() for x in varBind]))
            resultado= varB.split()[2]
    return resultado

def consultaSNMP2(comunidad,host,oid,puerto):
    errorIndication, errorStatus, errorIndex, varBinds = next(
        getCmd(SnmpEngine(),
               CommunityData(comunidad),
               UdpTransportTarget((host, puerto)),
               ContextData(),
               ObjectType(ObjectIdentity(oid))))

    if errorIndication:
        resultado=errorIndication
    elif errorStatus:
        print('%s at %s' % (errorStatus.prettyPrint(),errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
    else:
        for varBind in varBinds:
            varB=(' = '.join([x.prettyPrint() for x in varBind]))
            resultado= varB.split()[14]
    return resultado

def estadoAgente (lista):
    tamaño=int(len(lista))/4
    print("Número de agentes monitorizados",tamaño)
    i=0
    j=0
    while (i<tamaño):
        resultado=consultaSNMP(lista[j+1],lista[j],'1.3.6.1.2.1.1.1.0',lista[j+3])
        if(str(resultado)=="No SNMP response received before timeout"):
            print("Estado del agente",i+1,": down")
        else:
            print("Estado del agente",i+1,": up")
            resultado=consultaSNMP(lista[j+1],lista[j],'1.3.6.1.2.1.2.1.0',lista[j+3])
            print("El número de interfaces de red del agente",i+1,"son:", resultado)
            k=int(resultado)
            while (k>0):
                status="1.3.6.1.2.1.2.2.1.8."+str(k)
                desc="1.3.6.1.2.1.2.2.1.2."+str(k)
                resultado="La interfaz: "+str(consultaSNMP(lista[j+1],lista[j],desc,lista[j+3]))+", se encuentra (1=up, 2=down, 3=test):"+str(consultaSNMP(lista[j+1],lista[j],status,lista[j+3]))
                print(resultado)
                k=k-1
        i+=1
        j=j+4

def createRRD(nombre):
    nombre+=".rrd"
    ret = rrdtool.create(nombre,
                         "--start", 'N',
                         "--step", '15',
                         "DS:ifOutNUcastPkts:COUNTER:600:U:U",
                         "DS:ipOutRequest:COUNTER:600:U:U",
                         "DS:icmpInMsgs:COUNTER:600:U:U",
                         "DS:tcpRetransSegs:COUNTER:600:U:U",
                         "DS:udpOutDatagrams:COUNTER:600:U:U",
                         "RRA:AVERAGE:0.5:2:10",
                         "RRA:AVERAGE:0.5:1:20",
                         "RRA:AVERAGE:0.5:2:10",
                         "RRA:AVERAGE:0.5:1:20",
                         "RRA:AVERAGE:0.5:2:10")

    if ret:
        print(rrdtool.error())
    else :
        print("Creación satisfactoria")

def updateRRD (lista, agente, interfaz, nombre, tiempo):
    timeout = time.time() + tiempo
    xml=nombre+".xml"
    nombre+=".rrd"
    total_Mult_cast = 0
    total_out_Request = 0
    total_icmp_Msgs = 0
    total_tcp_retrans = 0
    total_udp_Dat = 0
    j=(agente-1)*4
    red="1.3.6.1.2.1.2.2.1.18."+str(interfaz)
    while 1:
        if time.time() > timeout:
            break
        total_Mult_cast = int(consultaSNMP(lista[j+1],lista[j],red,lista[j+3]))
        total_out_Request = int(consultaSNMP(lista[j+1],lista[j],"1.3.6.1.2.1.4.10.0",lista[j+3]))
        total_icmp_Msgs = int(consultaSNMP(lista[j+1],lista[j],"1.3.6.1.2.1.5.1.0",lista[j+3]))
        total_tcp_retrans = int(consultaSNMP(lista[j+1],lista[j],"1.3.6.1.2.1.6.12.0",lista[j+3]))
        total_udp_Dat = int(consultaSNMP(lista[j+1],lista[j],"1.3.6.1.2.1.7.4.0",lista[j+3]))

        valor = "N:" + str(total_Mult_cast) + ':' + str(total_out_Request) + ':' + str(total_icmp_Msgs) + ':' + str(total_tcp_retrans) + ':' + str(total_udp_Dat)
        print(valor)
        rrdtool.update(nombre, valor)
        rrdtool.dump(nombre, xml)
        time.sleep(1)

    #if ret:
     #   print(rrdtool.error())
      #  time.sleep(300)

def graphRRD(nombre, tiempo):
    tiempo_actual = int(time.time())
    # Grafica desde el tiempo actual menos diez minutos
    tiempo_inicial = tiempo_actual - tiempo

    ret = rrdtool.graph(nombre+"OutRequest.png",
                        "--start", str(tiempo_inicial),
                        "--end", "N",
                        "--vertical-label=Paquetes",
                        "--title=Número de paquetes IPv4 suministrados por protocolos locales \n Usando SNMP y RRDtools",
                        "DEF:ipOutRequest=" + nombre + ".rrd:ipOutRequest:AVERAGE",
                        "AREA:ipOutRequest#0000FF:Ipv4")

    ret = rrdtool.graph(nombre + "NUncast.png",
                        "--start", str(tiempo_inicial),
                        "--end", "N",
                        "--vertical-label=Mensajes multicast",
                        "--title=Número de mensajes multicast enviados \n Usando SNMP y RRDtools",
                        "DEF:ifOutNUcastPkts="+nombre+".rrd:ifOutNUcastPkts:AVERAGE",
                        "LINE2:ifOutNUcastPkts#00FF00:Multicast")
    ret = rrdtool.graph(nombre + "ICMP.png",
                        "--start", str(tiempo_inicial),
                        "--end", "N",
                        "--vertical-label=Mensajes",
                        "--title=Número de mensajes ICMP recibidos \n Usando SNMP y RRDtools",
                        "DEF:icmpInMsgs=" + nombre + ".rrd:icmpInMsgs:AVERAGE",
                        "AREA:icmpInMsgs#00FF00:ICMP")
    ret = rrdtool.graph(nombre + "TCP.png",
                        "--start", str(tiempo_inicial),
                        "--end", "N",
                        "--vertical-label=Segmentos",
                        "--title=Segmentos retransmitidos \n Usando SNMP y RRDtools",
                        "DEF:tcpRetransSegs=" + nombre + ".rrd:tcpRetransSegs:AVERAGE",
                        "AREA:tcpRetransSegs#00FF00:TCP")
    ret = rrdtool.graph(nombre + "UDP.png",
                        "--start", str(tiempo_inicial),
                        "--end", "N",
                        "--vertical-label=Datagramas",
                        "--title=Datagramas enviados \n Usando SNMP y RRDtools",
                        "DEF:udpOutDatagrams=" + nombre + ".rrd:udpOutDatagrams:AVERAGE",
                        "AREA:udpOutDatagrams#FF0000:UDP")

def creacion(lista):
    nombre=input("Nombre del archivo de rrd, xml y png: ")
    createRRD(nombre)
    agente=int(input("Indique el número del agente: "))
    interfaz=input("Seleccione el número de la interfaz de red para el archivo: ")
    tiempo=int(input("Tiempo de ejecuci+on de update en segundos: "))
    updateRRD(lista, agente, interfaz, nombre,tiempo)

def creacionGraph (lista):
    nombre = input("Ingresa el nombre del archivo rrd: ")
    tiempo = int(input("Ingresa el tiempo utlizado en segundos: "))
    graphRRD(nombre, tiempo)
    print("Operación exitosa\n\n")

def generarPDF (lista,agente,sistema):
    j=(agente-1)*4
    c=canvas.Canvas("Reporte del agente"+str(agente)+".pdf", pagesize=A4)
    h=A4
    if sistema == "windows":
        c.drawImage("Windows.jpeg", 20, h[1]-60, width=50, height=50)
        text = c.beginText(50, h[1] - 80)
        text.textLines(
            "\n\n\nNombre: " + str(consultaSNMP(lista[j + 1], lista[j], '1.3.6.1.2.1.1.5.0', lista[j + 3])) + "   "
            + "Version: " + str(consultaSNMP(lista[j + 1], lista[j], '1.3.6.1.2.1.1.2.0', lista[j + 3])) + "    "
            + "   SO: " + str(consultaSNMP2(lista[j + 1], lista[j], '1.3.6.1.2.1.1.1.0', lista[j + 3])) + "\n"
            + "Ubicacion: " + str(consultaSNMP(lista[j + 1], lista[j], '1.3.6.1.2.1.1.6.0', lista[j + 3])) + "\n"
            + "Puerto: " + str(lista[j + 3]) + " Tiempo de Actividad: " + str(
                consultaSNMP(lista[j + 1], lista[j], '1.3.6.1.2.1.1.3.0', lista[j + 3])) + "\n"
            + "Comunidad: " + str(lista[j + 1]) + " Ip: " + str(lista[j]))
        c.drawText(text)
        c.drawImage("agente" + str(agente) + "ICMP.png", 50, h[1] - 300, width=248, height=143)
        c.drawImage("agente" + str(agente) + "TCP.png", 310, h[1] - 300, width=248, height=143)
        c.drawImage("agente" + str(agente) + "UDP.png", 50, h[1] - 500, width=248, height=143)
        c.drawImage("agente" + str(agente) + "NUncast.png", 310, h[1] - 500, width=248, height=143)
        c.drawImage("agente" + str(agente) + "OutRequest.png", 50, h[1] - 700, width=248, height=143)
        c.showPage()
        c.save()
    else:
        c.drawImage("mint.png", 20, h[1]-60, width=50, height=50)
        text = c.beginText(50, h[1] - 80)
        text.textLines(
            "\n\n\nNombre: " + str(consultaSNMP(lista[j + 1], lista[j], '1.3.6.1.2.1.1.5.0', lista[j + 3])) + "   "
            + "Version: " + str(consultaSNMP(lista[j + 1], lista[j], '1.3.6.1.2.1.1.2.0', lista[j + 3])) + "    "
            + "   SO: " + str(consultaSNMP(lista[j + 1], lista[j], '1.3.6.1.2.1.1.1.0', lista[j + 3])) + "\n"
            + "Ubicacion: " + str(consultaSNMP(lista[j + 1], lista[j], '1.3.6.1.2.1.1.6.0', lista[j + 3])) + "\n"
            + "Puerto: " + str(lista[j + 3]) + " Tiempo de Actividad: " + str(
                consultaSNMP(lista[j + 1], lista[j], '1.3.6.1.2.1.1.3.0', lista[j + 3])) + "\n"
            + "Comunidad: " + str(lista[j + 1]) + " Ip: " + str(lista[j]))
        c.drawText(text)
        c.drawImage("agente" + str(agente) + "ICMP.png", 50, h[1] - 300, width=248, height=143)
        c.drawImage("agente" + str(agente) + "TCP.png", 310, h[1] - 300, width=248, height=143)
        c.drawImage("agente" + str(agente) + "UDP.png", 50, h[1] - 500, width=248, height=143)
        c.drawImage("agente" + str(agente) + "NUncast.png", 310, h[1] - 500, width=248, height=143)
        c.drawImage("agente" + str(agente) + "OutRequest.png", 50, h[1] - 700, width=248, height=143)
        c.showPage()
        c.save()

def reporte(lista):
    agente=int(input("Ingresa el agente: "))
    sistema=input("Ingresa el sistema del agente: ")
    generarPDF(lista, agente, sistema)

