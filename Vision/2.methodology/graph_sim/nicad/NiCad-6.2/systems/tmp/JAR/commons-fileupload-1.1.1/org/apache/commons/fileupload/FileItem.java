package org.apache.commons.fileupload;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;

public interface FileItem extends Serializable {
  InputStream getInputStream() throws IOException;
  
  String getContentType();
  
  String getName();
  
  boolean isInMemory();
  
  long getSize();
  
  byte[] get();
  
  String getString(String paramString) throws UnsupportedEncodingException;
  
  String getString();
  
  void write(File paramFile) throws Exception;
  
  void delete();
  
  String getFieldName();
  
  void setFieldName(String paramString);
  
  boolean isFormField();
  
  void setFormField(boolean paramBoolean);
  
  OutputStream getOutputStream() throws IOException;
}
