# RansonwareData
Repositório para análise dos dados sobre ransonware para o desenvolvimento de uma IA voltada à detecção do mesmo.

# Sobre o projeto

Ransomware é uma das ameaças cibernéticas mais relevantes da atualidade, caracterizando-se pela criptografia maliciosa de arquivos e posterior exigência de pagamento para a liberação dos dados. Esse tipo de ataque tem se expandido em frequência e sofisticação, afetando tanto usuários individuais quanto organizações de grande porte, resultando em prejuízos financeiros, interrupção de serviços e danos à reputação.

A evolução constante das variantes de ransomware torna as abordagens tradicionais de segurança — baseadas apenas em assinaturas ou listas de ameaças conhecidas — insuficientes. Nesse cenário, a aplicação de Inteligência Artificial surge como uma alternativa estratégica e eficaz. Modelos de aprendizado de máquina permitem identificar padrões anômalos de comportamento em tempo real, possibilitando a detecção precoce de atividades suspeitas e a mitigação do ataque antes que os arquivos sejam comprometidos.

Este projeto tem como objetivo explorar e desenvolver técnicas de detecção de ransomware com o uso de IA, oferecendo uma solução proativa que combina análise inteligente de dados e capacidade de adaptação frente a novas ameaças. Dessa forma, busca-se fortalecer a segurança dos sistemas e reduzir o impacto desses ataques no ambiente digital.

# Sobre o modelo

O Random Forest é um algoritmo de aprendizado de máquina baseado em conjuntos (ensemble), amplamente reconhecido pela sua eficácia em tarefas de classificação e regressão. Ele funciona por meio da combinação de múltiplas árvores de decisão, o que resulta em um modelo mais robusto, preciso e menos propenso ao overfitting.

### Como funciona

Treinamento: o modelo gera diversas árvores de decisão a partir de subconjuntos aleatórios dos dados de treinamento (bagging). Além disso, a cada divisão dos nós, apenas um subconjunto de variáveis é considerado, introduzindo diversidade no processo.

### Predição:

- Em problemas de classificação, a decisão final é determinada pelo voto majoritário das árvores.

- Em problemas de regressão, a predição final corresponde à média dos valores estimados pelas árvores.

### Vantagens

- Alta acurácia e desempenho consistente em diferentes domínios.

- Robustez contra ruído e outliers nos dados.

- Escalabilidade, capaz de lidar com grandes volumes de variáveis sem necessidade de pré-seleção complexa.

- Interpretação facilitada, por meio da análise da importância das variáveis para a tomada de decisão.

### Aplicações

O Random Forest é amplamente utilizado em áreas como análise de risco, detecção de anomalias, reconhecimento de padrões e segurança cibernética. Neste projeto, o modelo é aplicado à detecção de ransomware, permitindo identificar comportamentos suspeitos de forma proativa e aumentando a resiliência dos sistemas frente a ameaças digitais.

## Por que utilizar o Random Forest neste projeto

A escolha do Random Forest para este projeto de detecção de ransomware está alinhada à necessidade de um modelo preciso, robusto e escalável diante de um cenário de ameaças em constante evolução. Diferentemente de técnicas tradicionais de segurança, que dependem de assinaturas fixas ou regras estáticas, o Random Forest é capaz de aprender padrões complexos de comportamento e identificar anomalias mesmo em situações não previamente catalogadas.

Sua arquitetura baseada na combinação de múltiplas árvores de decisão garante maior generalização e reduz significativamente o risco de falsos positivos e falsos negativos. Além disso, o modelo fornece métricas de importância das variáveis, permitindo compreender quais características do sistema têm maior influência na detecção de atividades maliciosas.

Ao adotar o Random Forest, este projeto busca oferecer uma solução que alia eficiência técnica e confiabilidade prática, fortalecendo a defesa contra ataques de ransomware e contribuindo para a segurança de ambientes digitais críticos.

# Resultados

- Matriz de confusão:

<img width="750" height="430" alt="image" src="https://github.com/user-attachments/assets/f386607f-8df8-469e-b03c-e58bbb8eba46" />



