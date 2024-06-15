package org.apache.commons.fileupload;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import org.apache.commons.fileupload.servlet.ServletRequestContext;

public abstract class FileUploadBase {
  public static final String CONTENT_TYPE = "Content-type";
  
  public static final String CONTENT_DISPOSITION = "Content-disposition";
  
  public static final String FORM_DATA = "form-data";
  
  public static final String ATTACHMENT = "attachment";
  
  public static final String MULTIPART = "multipart/";
  
  public static final String MULTIPART_FORM_DATA = "multipart/form-data";
  
  public static final String MULTIPART_MIXED = "multipart/mixed";
  
  public static final int MAX_HEADER_SIZE = 1024;
  
  public static final boolean isMultipartContent(RequestContext ctx) {
    String contentType = ctx.getContentType();
    if (contentType == null)
      return false; 
    if (contentType.toLowerCase().startsWith("multipart/"))
      return true; 
    return false;
  }
  
  public static final boolean isMultipartContent(HttpServletRequest req) {
    if (!"post".equals(req.getMethod().toLowerCase()))
      return false; 
    String contentType = req.getContentType();
    if (contentType == null)
      return false; 
    if (contentType.toLowerCase().startsWith("multipart/"))
      return true; 
    return false;
  }
  
  private long sizeMax = -1L;
  
  private String headerEncoding;
  
  public abstract FileItemFactory getFileItemFactory();
  
  public abstract void setFileItemFactory(FileItemFactory paramFileItemFactory);
  
  public long getSizeMax() {
    return this.sizeMax;
  }
  
  public void setSizeMax(long sizeMax) {
    this.sizeMax = sizeMax;
  }
  
  public String getHeaderEncoding() {
    return this.headerEncoding;
  }
  
  public void setHeaderEncoding(String encoding) {
    this.headerEncoding = encoding;
  }
  
  public List parseRequest(HttpServletRequest req) throws FileUploadException {
    return parseRequest(new ServletRequestContext(req));
  }
  
  public List parseRequest(RequestContext ctx) throws FileUploadException {
    if (ctx == null)
      throw new NullPointerException("ctx parameter"); 
    ArrayList items = new ArrayList();
    String contentType = ctx.getContentType();
    if (null == contentType || !contentType.toLowerCase().startsWith("multipart/"))
      throw new InvalidContentTypeException("the request doesn't contain a multipart/form-data or multipart/mixed stream, content type header is " + contentType); 
    int requestSize = ctx.getContentLength();
    if (requestSize == -1)
      throw new UnknownSizeException("the request was rejected because its size is unknown"); 
    if (this.sizeMax >= 0L && requestSize > this.sizeMax)
      throw new SizeLimitExceededException("the request was rejected because its size (" + requestSize + ") exceeds the configured maximum (" + this.sizeMax + ")", requestSize, this.sizeMax); 
    String charEncoding = this.headerEncoding;
    if (charEncoding == null)
      charEncoding = ctx.getCharacterEncoding(); 
    try {
      byte[] boundary = getBoundary(contentType);
      if (boundary == null)
        throw new FileUploadException("the request was rejected because no multipart boundary was found"); 
      InputStream input = ctx.getInputStream();
      MultipartStream multi = new MultipartStream(input, boundary);
      multi.setHeaderEncoding(charEncoding);
      boolean nextPart = multi.skipPreamble();
      while (nextPart) {
        Map headers = parseHeaders(multi.readHeaders());
        String fieldName = getFieldName(headers);
        if (fieldName != null) {
          String subContentType = getHeader(headers, "Content-type");
          if (subContentType != null && subContentType.toLowerCase().startsWith("multipart/mixed")) {
            byte[] subBoundary = getBoundary(subContentType);
            multi.setBoundary(subBoundary);
            boolean nextSubPart = multi.skipPreamble();
            while (nextSubPart) {
              headers = parseHeaders(multi.readHeaders());
              if (getFileName(headers) != null) {
                FileItem item = createItem(headers, false);
                OutputStream os = item.getOutputStream();
                try {
                  multi.readBodyData(os);
                } finally {
                  os.close();
                } 
                items.add(item);
              } else {
                multi.discardBodyData();
              } 
              nextSubPart = multi.readBoundary();
            } 
            multi.setBoundary(boundary);
          } else {
            FileItem item = createItem(headers, (getFileName(headers) == null));
            OutputStream os = item.getOutputStream();
            try {
              multi.readBodyData(os);
            } finally {
              os.close();
            } 
            items.add(item);
          } 
        } else {
          multi.discardBodyData();
        } 
        nextPart = multi.readBoundary();
      } 
    } catch (IOException e) {
      throw new FileUploadException("Processing of multipart/form-data request failed. " + e.getMessage());
    } 
    return items;
  }
  
  protected byte[] getBoundary(String contentType) {
    byte[] boundary;
    ParameterParser parser = new ParameterParser();
    parser.setLowerCaseNames(true);
    Map params = parser.parse(contentType, ';');
    String boundaryStr = (String)params.get("boundary");
    if (boundaryStr == null)
      return null; 
    try {
      boundary = boundaryStr.getBytes("ISO-8859-1");
    } catch (UnsupportedEncodingException e) {
      boundary = boundaryStr.getBytes();
    } 
    return boundary;
  }
  
  protected String getFileName(Map headers) {
    String fileName = null;
    String cd = getHeader(headers, "Content-disposition");
    if (cd != null) {
      String cdl = cd.toLowerCase();
      if (cdl.startsWith("form-data") || cdl.startsWith("attachment")) {
        ParameterParser parser = new ParameterParser();
        parser.setLowerCaseNames(true);
        Map params = parser.parse(cd, ';');
        if (params.containsKey("filename")) {
          fileName = (String)params.get("filename");
          if (fileName != null) {
            fileName = fileName.trim();
          } else {
            fileName = "";
          } 
        } 
      } 
    } 
    return fileName;
  }
  
  protected String getFieldName(Map headers) {
    String fieldName = null;
    String cd = getHeader(headers, "Content-disposition");
    if (cd != null && cd.toLowerCase().startsWith("form-data")) {
      ParameterParser parser = new ParameterParser();
      parser.setLowerCaseNames(true);
      Map params = parser.parse(cd, ';');
      fieldName = (String)params.get("name");
      if (fieldName != null)
        fieldName = fieldName.trim(); 
    } 
    return fieldName;
  }
  
  protected FileItem createItem(Map headers, boolean isFormField) throws FileUploadException {
    return getFileItemFactory().createItem(getFieldName(headers), getHeader(headers, "Content-type"), isFormField, getFileName(headers));
  }
  
  protected Map parseHeaders(String headerPart) {
    Map headers = new HashMap();
    char[] buffer = new char[1024];
    boolean done = false;
    int j = 0;
    try {
      while (!done) {
        int i = 0;
        while (i < 2 || buffer[i - 2] != '\r' || buffer[i - 1] != '\n')
          buffer[i++] = headerPart.charAt(j++); 
        String header = new String(buffer, 0, i - 2);
        if (header.equals("")) {
          done = true;
          continue;
        } 
        if (header.indexOf(':') == -1)
          continue; 
        String headerName = header.substring(0, header.indexOf(':')).trim().toLowerCase();
        String headerValue = header.substring(header.indexOf(':') + 1).trim();
        if (getHeader(headers, headerName) != null) {
          headers.put(headerName, getHeader(headers, headerName) + ',' + headerValue);
          continue;
        } 
        headers.put(headerName, headerValue);
      } 
    } catch (IndexOutOfBoundsException e) {}
    return headers;
  }
  
  protected final String getHeader(Map headers, String name) {
    return (String)headers.get(name.toLowerCase());
  }
  
  public static class InvalidContentTypeException extends FileUploadException {
    public InvalidContentTypeException() {}
    
    public InvalidContentTypeException(String message) {
      super(message);
    }
  }
  
  public static class UnknownSizeException extends FileUploadException {
    public UnknownSizeException() {}
    
    public UnknownSizeException(String message) {
      super(message);
    }
  }
  
  public static class SizeLimitExceededException extends FileUploadException {
    private long actual;
    
    private long permitted;
    
    public SizeLimitExceededException() {}
    
    public SizeLimitExceededException(String message) {
      super(message);
    }
    
    public SizeLimitExceededException(String message, long actual, long permitted) {
      super(message);
      this.actual = actual;
      this.permitted = permitted;
    }
    
    public long getActualSize() {
      return this.actual;
    }
    
    public long getPermittedSize() {
      return this.permitted;
    }
  }
}
