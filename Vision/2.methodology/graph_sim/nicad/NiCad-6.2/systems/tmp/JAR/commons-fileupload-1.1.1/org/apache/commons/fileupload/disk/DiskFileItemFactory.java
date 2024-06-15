package org.apache.commons.fileupload.disk;

import java.io.File;
import org.apache.commons.fileupload.FileItem;
import org.apache.commons.fileupload.FileItemFactory;

public class DiskFileItemFactory implements FileItemFactory {
  public static final int DEFAULT_SIZE_THRESHOLD = 10240;
  
  private File repository;
  
  private int sizeThreshold = 10240;
  
  public DiskFileItemFactory() {}
  
  public DiskFileItemFactory(int sizeThreshold, File repository) {
    this.sizeThreshold = sizeThreshold;
    this.repository = repository;
  }
  
  public File getRepository() {
    return this.repository;
  }
  
  public void setRepository(File repository) {
    this.repository = repository;
  }
  
  public int getSizeThreshold() {
    return this.sizeThreshold;
  }
  
  public void setSizeThreshold(int sizeThreshold) {
    this.sizeThreshold = sizeThreshold;
  }
  
  public FileItem createItem(String fieldName, String contentType, boolean isFormField, String fileName) {
    return new DiskFileItem(fieldName, contentType, isFormField, fileName, this.sizeThreshold, this.repository);
  }
}
