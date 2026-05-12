import torch
from transformers import AutoProcessor, AutoModelForMultimodalLM, BitsAndBytesConfig
import numpy as np

class GemmaTranscriber:
    def __init__(self, model_id="google/gemma-4-E2B-it", device="cuda" if torch.cuda.is_available() else "cpu"):
        self.device = device
        print(f"Loading model {model_id} on {device}...")
        self.processor = AutoProcessor.from_pretrained(model_id)
        
        # Configure 4-bit quantization if CUDA is available
        quantization_config = None
        if torch.cuda.is_available():
            quantization_config = BitsAndBytesConfig(
                load_in_4bit=True,
                bnb_4bit_compute_dtype=torch.bfloat16,
                bnb_4bit_use_double_quant=True,
                bnb_4bit_quant_type="nf4"
            )
        
        self.model = AutoModelForMultimodalLM.from_pretrained(
            model_id, 
            dtype=torch.bfloat16,
            device_map="auto",
            low_cpu_mem_usage=True,
            quantization_config=quantization_config
        )
        

    def transcribe(self, audio_data, samplerate=16000):
        """
        Transcribes the given audio data.
        audio_data: numpy array of shape (N,) or (N, 1)
        """
        if len(audio_data) == 0:
            return ""

        # Ensure audio is float32 and normalized
        if audio_data.dtype != np.float32:
            audio_data = audio_data.astype(np.float32)
        
        # Multimodal models usually expect a prompt
        prompt = "<audio>Transcribe the audio."
        
        inputs = self.processor(
            text=prompt,
            audios=audio_data,
            sampling_rate=samplerate,
            return_tensors="pt"
        ).to(self.device)

        with torch.no_grad():
            generated_ids = self.model.generate(**inputs, max_new_tokens=256)
        
        # Decode only the new tokens
        output_text = self.processor.batch_decode(
            generated_ids[:, inputs["input_ids"].shape[1]:], 
            skip_special_tokens=True
        )[0]
        
        return output_text.strip()

if __name__ == "__main__":
    # Test with dummy audio
    transcriber = GemmaTranscriber()
    dummy_audio = np.zeros(16000, dtype=np.float32)
    print("Test transcription:", transcriber.transcribe(dummy_audio))
