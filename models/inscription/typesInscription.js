import { gql } from 'apollo-server-express';

const typesInscription = gql`
  type Inscripcion {
    _id: ID!
    estado: Enum_EstadoInscripcion!
    fechaIngreso: Date
    fechaEgreso: Date
    proyecto(lider: String): Proyecto
    estudiante: Usuario!
  }
  type Query {
    Inscripciones: [Inscripcion]
  }
  type Mutation {
    crearInscripcion(proyecto: String!, estudiante: String!): Inscripcion
    aprobarInscripcion(id: String!): Inscripcion
    rechazarInscripcion(id: String!): Inscripcion
  }
`;

export { typesInscription };
