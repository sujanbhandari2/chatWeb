import { useMutation } from '@tanstack/react-query';
import { uploadFileRequest } from '../api/upload.api';

export const useUploadFileMutation = () =>
  useMutation({
    mutationFn: (file: File) => uploadFileRequest(file)
  });
