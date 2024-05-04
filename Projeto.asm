.686
.model flat, stdcall
option casemap:none

include \masm32\include\windows.inc
include \masm32\include\kernel32.inc
include \masm32\include\masm32.inc
includelib \masm32\lib\kernel32.lib
includelib \masm32\lib\masm32.lib

;***********************************************************************
;| PROJETO DA DISCIPLINA ARQUITETURA DE COMPUTADORES 1 - UFPB - 2024.1 |
;|*********************************************************************|
;| DESENVOLVIDO PELOS ALUNOS:                                          |
;|   LEANDESON PINHEIRO SANTOS DE ARAUJO - 20230144958                 |
;|   JOÃO VITOR TEIXERA BARRETO - 20210094349                          |
;|   KAUA PEREIRA VIANA - 20230089631                                  |
;***********************************************************************


.data
    ;PRINTS DA CONSOLE
    str_title     db "--------- Cifra de Transposicao ---------", 0AH, 0H                       
    str_request_3 db 0AH, "Entre a chave de transposicao", 0AH, 0H  
    str_request_2 db 0AH, "Entre o caminho do arquivo de saida", 0AH, 0H
    str_request_1 db 0AH, "Entre o caminho do arquivo de entrada", 0AH, 0H
    str_options   db 0AH, "[1]Criptografar [2]Descriptografar [0]Sair", 0AH, 0H

    opt1_succeed db 0AH, "Criptografia realizada com sucesso!", 0AH, 0H
    opt2_succeed db 0AH, "Descriptografia realizada com sucesso!", 0AH, 0H
    opt3_succeed db "Fechando programa...", 0AH, 0H
    str_prompt   db ">> ", 0H


    ;PARAMETROS DE ACESSO DA CONSOLE
    input_handle dd 0
    output_handle dd 0
    console_count dd 0


    ;PARAMETROS DE ACESSO DOS ARQUIVOS
    input_file_handle dd 0
    output_file_handle dd 0
    count_read dd 0        
    count_write dd 0
  

    ;BUFFERS DE LEITURA E ESCRITA
    console_buffer db 50 dup(0)
    input_file_buffer db 8 dup(0)
    output_file_buffer db 8 dup(0)
    

    ;ARRAY PARA RECEBER DIGITOS DA CHAVE
    key_numeric dd 8 dup(0)

.code

;FUNÇÃO PARA CONVERTER STRING DE NUMEROS EM ARRAY DOWRD
Convert:
    push ebp
    mov ebp, esp
    
    mov esi, [ebp+8]                    ;String
    mov edi, [ebp+12]                   ;Array dword
    xor ecx, ecx

    converter:
        mov al, [esi + ecx]             ;Carregando o caractere da string em al
        sub al, '0'                     ;Converte o caractere ASCII para valor numerico
        mov [edi + ecx * 4], al         ;Armazena o valor numerico no array dword

        inc ecx
        cmp ecx, 8
    jne converter

    pop ebp
ret 8



;FUNÇÃO PARA REMOVER CARRIGERETURN DA STRING
RemoveCR:
    push ebp
    mov ebp, esp

    mov esi, [ebp+8]                    ;String
    proximo:
        mov al, [esi]                   ;Move o caracterer atual para al
        inc esi                         ;Incrementa o indice na String
        cmp al, 13                      ;Comparando caracterer com valor do CR
        jne proximo
        dec esi
        xor al, al                      ;Al recebe zero
        mov [esi], al                   ;Colocando \0 no lugar do CR
        
   pop ebp
ret 4



;FUNÇÃO PARA LIMPAR O BUFFER DO ARQUIVO DE ENTRADA
CleanFileBuffer:
    push ebp
    mov ebp, esp
    mov esi, [ebp+8]                            ;Buffer do arquivo de entrada

    xor ecx, ecx                                ;Setando contador para 0
    limpar:
        mov byte ptr[esi + ecx], 0              ;Colocando 0 no buffer posição ecx (buffer[ecx] = 0)
        inc ecx                                 ;incrementa contador
        cmp ecx, 8                              ;loop de 8 iterações
    jne limpar

    pop ebp
ret 4


;FUNÇÃO PARA CIFRAR
Cipher:
    push ebp
    mov ebp, esp

    cifrar:
        push [ebp+8]
        call CleanFileBuffer                                                                        ;Limpando buffer de entrada
        
        invoke ReadFile, input_file_handle, [ebp+8], 8, addr count_read, NULL                       ;Preenchendo buffer com dados do arq de entrada
        cmp count_read, 0                                                                           ;0 caracteres lidos significa fim do arquivo
            je fim_cifrar                                                                           ;Parar cifragem

        mov esi, [ebp+8]                                                                            ;Esi aponta para buffer do arq de entrada
        mov edi, [ebp+12]                                                                           ;Edi aponta para o buffer do arq de saida
        mov edx, [ebp+16]                                                                           ;Edx aponta para o array dword
        xor ecx, ecx                                                                                ;Zerando contador
        
        embaralhando:                                                                               ;Laço para preencher buffer de saida
            mov ebx, [edx + ecx * 4]                                                                ;Ebx recebe um digito da chave
            mov al, [esi + ecx]                                                                     ;Al recebe um caracter do buffer de entrada
            mov byte ptr[edi + ebx], al                                                             ;Move o caracter para o buffer de saida (buffer[ebx] = al)

            inc ecx
            cmp ecx, 8
        jne embaralhando

        invoke WriteFile, output_file_handle, [ebp+12], 8, addr count_write, NULL                   ;Descarrega dados do buffer no arq de saida
    jmp cifrar
    
    fim_cifrar:
    invoke WriteConsole, output_handle, addr opt1_succeed, sizeof opt1_succeed, addr console_count, NULL

    pop ebp
ret 12


    
;FUNÇÃO PARA DECIFRAR ARQUIVO
Decipher:
    push ebp
    mov ebp, esp

    decifrar:
        push offset input_file_buffer
        call CleanFileBuffer                                                                        ;Limpando buffer de entrada
        
        invoke ReadFile, input_file_handle, [ebp+8], 8, addr count_read, NULL                       ;Preenchendo buffer com dados do arq de entrada
        cmp count_read, 0                                                                           ;0 caracteres lidos significa fim do arquivo
            je fim_decifrar                                                                         ;Parar decifragem

        mov esi, [ebp+8]                                                                            ;Esi aponta para o buffer do arq de entrada
        mov edi, [ebp+12]                                                                           ;Edi aponta para o buffer do arq de saida
        mov edx, [ebp+16]                                                                           ;Edx aponta para a array dword
        xor ecx, ecx                                                                                ;Zerando contador
        
        desembaralha:                                                                               ;Laço para preencher o buffer de saida
            mov ebx, [edx + ecx * 4]                                                                ;Ebx recebe um digito da chave
            mov al, [esi + ebx]                                                                     ;Al recebe um caracter do buffer de entrada
            mov byte ptr[edi + ecx], al                                                             ;Move o caracter para o buffer de saida (buffer[ecx] = al)

            inc ecx
            cmp ecx, 8
        jne desembaralha

        invoke WriteFile, output_file_handle, [ebp+12], 8, addr count_write, NULL                   ;Descarrega dados do buffer no arq de saida
    jmp decifrar
    
    fim_decifrar:
    invoke WriteConsole, output_handle, addr opt2_succeed, sizeof opt2_succeed, addr console_count, NULL

    pop ebp
ret 12



;SOLICITA O ARQUIVO DE ENTRADA E SALVA SEU APONTADOR NA VARIAVEL INPUT_FILE_HANDLE
RequestInputFile:
    invoke WriteConsole, output_handle, addr str_request_1, sizeof str_request_1, addr console_count, NULL
    invoke WriteConsole, output_handle, addr str_prompt, sizeof str_prompt, addr console_count, NULL
    invoke ReadConsole, input_handle, addr console_buffer, sizeof console_buffer, addr console_count, NULL

    push offset console_buffer
    call RemoveCR
    
    invoke CreateFile, addr console_buffer, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
    mov input_file_handle, eax
ret



;SOLICITA O ARQUIVO DE SAIDA E SALVA SEU APONTADOR NA VARIAVEL OUT_FILE_HANDLE
RequestOutputFile:
    invoke WriteConsole, output_handle, addr str_request_2, sizeof str_request_2, addr console_count, NULL
    invoke WriteConsole, output_handle, addr str_prompt, sizeof str_prompt, addr console_count, NULL
    invoke ReadConsole, input_handle, addr console_buffer, sizeof console_buffer, addr console_count, NULL

    push offset console_buffer
    call RemoveCR

    invoke CreateFile, addr console_buffer, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL
    mov output_file_handle, eax
ret



;SOLICITA A CHAVE PARA CRIPTOGRAFIA
RequestKey:
    invoke WriteConsole, output_handle, addr str_request_3, sizeof str_request_3, addr console_count, NULL
    invoke WriteConsole, output_handle, addr str_prompt, sizeof str_prompt, addr console_count, NULL
    invoke ReadConsole, input_handle, addr console_buffer, sizeof console_buffer, addr console_count, NULL

    push offset console_buffer
    call RemoveCR

    push offset key_numeric                         ;Array dword de 8 posições
    push offset console_buffer                      ;String de numeros sem carrige return
    call Convert                                    ;Convertendo string de numeros em array dword
ret



;SOLICITA QUE O USUARIO ESCOLHA UMA OPÇÃO
ShowOptions:
    invoke WriteConsole, output_handle, addr str_options, sizeof str_options, addr console_count, NULL
    invoke WriteConsole, output_handle, addr str_prompt, sizeof str_prompt, addr console_count, NULL
    invoke ReadConsole, input_handle, addr console_buffer, sizeof console_buffer, addr console_count, NULL

    push offset console_buffer
    call RemoveCR

    ;Convertendo ASCII em Dword, retorno em eax
    invoke atodw, addr console_buffer
ret

;MOSTRA O MENU DO PROGRAMA
Menu:
    call ShowOptions                            ;Mostrando opções
        
    cmp eax, 1                                  ;Estrutura de instruções que simula um switch case
        je caso_1                               ;Opção 1 Cifragem
    cmp eax, 2                                  ;Opção 2 Decifragem
        je caso_2
        
    jmp fim_casos                               ;Qualquer outra entrada fecha o programa
        caso_1:

            call RequestInputFile
            call RequestOutputFile
            call RequestKey

            push offset key_numeric
            push offset output_file_buffer
            push offset input_file_buffer
            call Cipher

            jmp fim_casos
       caso_2:

            call RequestInputFile
            call RequestOutputFile
            call RequestKey

            push offset key_numeric
            push offset output_file_buffer
            push offset input_file_buffer
            call Decipher
            
     fim_casos:
ret

start:
    invoke GetStdHandle, STD_INPUT_HANDLE
    mov input_handle, eax
    invoke GetStdHandle, STD_OUTPUT_HANDLE
    mov output_handle, eax

    invoke WriteConsole, output_handle, addr str_title, sizeof str_title, addr console_count, NULL
    call Menu

    invoke CloseHandle, input_file_handle
    invoke CloseHandle, output_file_handle
    
    invoke WriteConsole, output_handle, addr opt3_succeed, sizeof opt3_succeed, addr console_count, NULL
    invoke ExitProcess, 0
end start