package org.apache.commons.fileupload;

import java.io.File;
import org.apache.commons.fileupload.disk.DiskFileItemFactory;

public class DefaultFileItemFactory extends DiskFileItemFactory {
  public DefaultFileItemFactory() {}
  
  public DefaultFileItemFactory(int sizeThreshold, File repository) {
    super(sizeThreshold, repository);
  }
  
  public FileItem createItem(String fieldName, String contentType, boolean isFormField, String fileName) {
    return new DefaultFileItem(fieldName, contentType, isFormField, fileName, getSizeThreshold(), getRepository());
  }
}
