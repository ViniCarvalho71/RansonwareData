# Relatorio de testes com logs Sysmon

Logs processados: 4
Eventos totais: 685

## Metricas (assumindo todos os eventos como ransomware)
- accuracy: 0.9766
- recall: 0.9766

## Predicao por log
- cerber.evtx: RANSOMWARE (rate=1.00, avg_prob=0.432)
- locky.evtx: RANSOMWARE (rate=0.82, avg_prob=0.422)
- teslacrypt.evtx: RANSOMWARE (rate=0.89, avg_prob=0.433)
- wannacry.evtx: RANSOMWARE (rate=0.97, avg_prob=0.414)

## Resumo por log
      _log_file  total_events  predicted_ransomware_rate  avg_prob_ransomware  max_prob_ransomware  log_pred_label
    cerber.evtx           478                   1.000000             0.432123             0.837295               1
     locky.evtx            33                   0.818182             0.421836             0.837295               1
teslacrypt.evtx            64                   0.890625             0.432993             0.843734               1
  wannacry.evtx           110                   0.972727             0.413617             0.837295               1

Arquivos gerados:
- C:\Projetos\RansonwareData\Tests\Reports\predictions_by_event.csv
- C:\Projetos\RansonwareData\Tests\Reports\summary_by_log.csv
- C:\Projetos\RansonwareData\Tests\Reports\logs_dataset_for_predict.csv