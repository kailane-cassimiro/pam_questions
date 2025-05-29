#include <security/pam_modules.h>  
#include <security/pam_ext.h> 
#include <security/pam_appl.h> 
#include <pwd.h> 
#include <stdio.h> 
#include <stdlib.h> 
#include <string.h> 
#include <unistd.h> 
#include <sys/stat.h> 

#define CONFIG_DIR ".pam_questions" 
#define CONFIG_FILE "config" 
#define MAX_LINE 128 
#define MAX_ANSWER 128 

// Remove o \\n no final da string 
void aparar(char *str) 
{ 
    size_t len = strlen(str); 
    if (len > 0 && str[len - 1] == '\n') str[len - 1] = '\0'; 
} 

// Cria o diretório ~/.pam_questions, se não existir 
void configurarDiretorio(const char *home) { 
    char caminho[512]; 
    printf(caminho, sizeof(caminho), "%s/%s", home, CONFIG_DIR); 
    mkdir(caminho, 0700); // Só o dono pode acessar 
} 

// Caminho completo para ~/.pam_questions/config 
void configurarCaminho(const char *home, char *out_path, size_t size) 
{ 
    printf(out_path, size, "%s/%s/%s", home, CONFIG_DIR, CONFIG_FILE); 
} 

// Pede uma entrada ao usuário 
int perguntaUsuario(pam_handle_t *pamh, const char *prompt, int echo, char *out, size_t out_size) 
{ 
    const struct pam_conv *conv; 
    struct pam_message mensagem; 
    const struct pam_message *mensagemPergunta; 
    struct pam_response *resp; 

    pam_get_item(pamh, PAM_CONV, (const void **)&conv); 
    mensagem.msg_style = echo ? PAM_PROMPT_ECHO_ON : PAM_PROMPT_ECHO_OFF; 
    mensagem.msg = prompt; 
    mensagemPergunta = &mensagem; 

    int ret = conv->conv(1, &mensagemPergunta, &resp, conv->appdata_ptr); 

    if (ret != PAM_SUCCESS || resp == NULL || resp->resp == NULL) return PAM_CONV_ERR; 

    strncpy(out, resp->resp, out_size); 
    free(resp->resp); 
    free(resp); 

    return PAM_SUCCESS; 
} 

// Lê pergunta e resposta do arquivo config 
int leituraArquivo(const char *filepath, char *pergunta, char *resposta) 
{ 
    FILE *file = fopen(filepath, "r"); 
    if (!file) return -1; 
    char linha[MAX_LINE]; 
    
    while (fgets(linha, sizeof(linha), file)) 
    { 
        aparar(linha); 
        if (strncmp(linha, "pergunta=", 9) == 0) 
        { 
            strncpy(pergunta, linha + 9, MAX_LINE); 
        } 
        else if (strncmp(linha, "resposta=", 9) == 0) 
        { 
            strncpy(resposta, linha + 9, MAX_ANSWER); 
        } 

    } 
    
    fclose(file); 
    return 0; 
} 

// Salva pergunta e resposta no arquivo config 
int salvarArquivoPergunta(const char *filepath, const char *pergunta, const char *resposta) 
{ 
    FILE *file = fopen(filepath, "w"); 
    if (!file) return -1; 

    fprintf(file, "pergunta=%s\nresposta=%s\n", pergunta, resposta); 
    fclose(file); 

    chmod(filepath, 0600); // Só o usuário pode ler/escrever 
    return 0; 
} 

// Função principal de autenticação 
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) 
{ 

    const char *username; 
    struct passwd *pwd; 

    char pergunta[MAX_LINE] = ""; 
    char resposta[MAX_ANSWER] = ""; 
    char resposta_usuario[MAX_ANSWER] = ""; 

    char filepath[512]; 

    if (pam_get_user(pamh, &username, NULL) != PAM_SUCCESS) return PAM_AUTH_ERR; 

    //Root não precisa da autenticação 

    if (strcmp(username, "root") == 0) 
        return PAM_SUCCESS; 

    pwd = getpwnam(username); 

    if (!pwd) return PAM_AUTH_ERR; 

    configurarDiretorio(pwd->pw_dir); 
    configurarCaminho(pwd->pw_dir, filepath, sizeof(filepath)); 

    // Se o arquivo não existir, pede pergunta e resposta e salva 
    if (access(filepath, F_OK) != 0) 
    { 
        char nova_pergunta[MAX_LINE], nova_resposta[MAX_ANSWER]; 

        if (perguntaUsuario(pamh, "Defina uma pergunta pessoal: ", 1, nova_pergunta, sizeof(nova_pergunta)) != PAM_SUCCESS) return PAM_AUTH_ERR; 
        if (perguntaUsuario(pamh, "Resposta para a pergunta: ", 1, nova_resposta, sizeof(nova_resposta)) != PAM_SUCCESS) return PAM_AUTH_ERR; 

        salvarArquivoPergunta(filepath, nova_pergunta, nova_resposta); 

        return PAM_SUCCESS; 
    } 

    // Caso já exista, carregue e compare 
    if (leituraArquivo(filepath, pergunta, resposta) != 0) return PAM_AUTH_ERR; 
    if (perguntaUsuario(pamh, pergunta, 1, resposta_usuario, sizeof(resposta_usuario)) != PAM_SUCCESS) return PAM_AUTH_ERR; 

    aparar(resposta); 
    aparar(resposta_usuario); 

    if (strcmp(resposta, resposta_usuario) == 0) return PAM_SUCCESS; 

    return PAM_AUTH_ERR; 
} 

// Função obrigatória
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) 
{ 
    return PAM_SUCCESS; 
} 

// Função obrigatória
PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) 
{ 
    return PAM_SUCCESS; 
} 

// Função obrigatória
PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) 
{ 
    return PAM_SUCCESS; 
} 
